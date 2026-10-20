package th_tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/tidwall/gjson"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type JWTSession struct {
	ID  string
	Exp time.Time
	Iat time.Time
}

type System struct {
	Id   bson.ObjectId `bson:"_id,omitempty" json:"_id"`
	Name string
}

type AccountSystem struct {
	Role     string
	SystemId bson.ObjectId `bson:"systemId"`
	Details  bson.M        `bson:",inline"`
}

type AccountMGO struct {
	Id          bson.ObjectId `bson:"_id,omitempty" json:"_id"`
	Email       string
	Password    string          `json:"-"`
	IsActive    bool            `bson:"isActive"`
	DateCreated time.Time       `bson:"dateCreated"`
	Token       string          `bson:"resetToken"`
	Systems     []AccountSystem `bson:"systems"`
}

var (
	storeMu sync.Mutex
	store   *sessions.CookieStore
)

// sessionStore returns the cookie store, keyed with "session_key" from the config
func sessionStore(r *http.Request) (*sessions.CookieStore, error) {
	storeMu.Lock()
	defer storeMu.Unlock()

	if store == nil {
		config := context.Get(r, "config").([]byte)
		key := gjson.GetBytes(config, "session_key").String()

		if len(key) < 32 {
			return nil, errors.New("config: session_key must be at least 32 characters")
		}

		store = sessions.NewCookieStore([]byte(key))
	}

	return store, nil
}

// accessToken returns the JWT from the session cookie or the Authorization header
func accessToken(r *http.Request, session *sessions.Session) string {
	if token, ok := session.Values["access_token"].(string); ok && len(token) > 0 {
		return token
	}

	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}

	return ""
}

func (a *AccountMGO) ConvertPassword() error {
	hash, err := HashPassword(a.Password)
	if err != nil {
		return err
	}

	a.Password = hash

	return nil
}

func (a *AccountMGO) Sanitize(account gjson.Result, confirm bool) error {

	// TODO actual validation
	email := account.Get("Email").Str
	password := account.Get("Password").Str

	a.Email = email

	if true == confirm {
		passwordConfirm := account.Get("PasswordConfirm").Str

		if password != passwordConfirm {
			return errors.New("Password != PasswordConfirm")
		}
	}

	a.Password = password

	return nil
}

func (a AccountMGO) Validate(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "Het inloggen is mislukt."

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "json", response, err
	}
	account := gjson.Parse(string(body))

	a.Sanitize(account, false)
	password := a.Password

	db := context.Get(r, "mongodb").(*mgo.Session)
	c := db.DB("quran").C("accounts")

	err = c.Find(bson.M{"email": a.Email}).One(&a)
	if err != nil {
		return "json", response, err
	}

	ok, rehash := CheckPassword(a.Password, password)
	if !ok {
		return "json", response, errors.New("invalid email or password")
	}

	if rehash {
		// upgrade legacy SHA-512 hash to bcrypt
		if hash, err := HashPassword(password); err == nil {
			if err := c.UpdateId(a.Id, bson.M{"$set": bson.M{"password": hash}}); err != nil {
				log.Println(err)
			}
		}
	}

	config := context.Get(r, "config").([]byte)
	secret := []byte(gjson.GetBytes(config, "secret").String())

	now := time.Now()
	duration, _ := time.ParseDuration("1h")
	expire := now.Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id": a.Id.String(),
		"iat": now.Unix(),
		"exp": expire,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "json", response, err
	}

	store, err := sessionStore(r)
	if err != nil {
		return "json", response, err
	}

	session, err := store.Get(r, "session")
	if err != nil {
		return "json", response, err
	}

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(duration.Seconds()),
		HttpOnly: true,
	}
	session.Values["access_token"] = tokenString
	session.Save(r, w)

	response.Success(tokenString)

	return "json", response, nil
}

func check(secret []byte, tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// tokens are signed with a shared HMAC secret, reject any other algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	// expired tokens are rejected here as well (jwt.ErrTokenExpired)
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	return claims, nil
}

func (a AccountMGO) Check(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd."

	store, err := sessionStore(r)
	if err != nil {
		return "json", response, err
	}

	session, err := store.Get(r, "session")
	if err != nil {
		return "json", response, err
	}

	tokenString := accessToken(r, session)

	if len(tokenString) > 0 {
		config := context.Get(r, "config").([]byte)
		secret := []byte(gjson.GetBytes(config, "secret").String())

		_, err := check(secret, tokenString)
		if err != nil {
			return "json", response, err
		}

		response.Success(tokenString)

		session.Values["access_token"] = tokenString
		session.Save(r, w)
	}

	return "json", response, nil
}

func (a AccountMGO) RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		deny := func() {
			response := Response{}

			response.Status = "error"
			response.Body = "U bent niet ingelogd of uw sessie is verlopen."

			json.NewEncoder(w).Encode(response)
		}

		config := context.Get(r, "config").([]byte)
		secret := []byte(gjson.GetBytes(config, "secret").String())

		store, err := sessionStore(r)
		if err != nil {
			log.Println(err)
			deny()
			return
		}

		session, err := store.Get(r, "session")
		if err != nil {
			deny()
			return
		}

		if _, err := check(secret, accessToken(r, session)); err != nil {
			deny()
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a AccountMGO) Register(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "De registratie is mislukt."

	/*
		values, err := jason.NewObjectFromReader(r.Body)
		if err != nil {
			return "json", response, err
		}

		if false == check(r) {

			db := context.Get(r, "mongodb").(*mgo.Session)
			accounts := db.DB("auth").C("accounts")
			systems := db.DB("auth").C("systems")

			err = a.Sanitize(values, true)
			if err != nil {
				response.Error("Uw wachtwoord komt niet overeen met de verificatie.")
				return "json", response, err
			}

			err = a.ConvertPassword()
			if err != nil {
				return "json", response, err
			}

			a.IsActive = true
			a.DateCreated = time.Now()

			s := System{}
			systems.Find(bson.M{"name": context.Get(r, "system").(string)}).One(&s)

			a.Systems = []AccountSystem{AccountSystem{
				Role:     "user",
				SystemId: s.Id,
				Details:  bson.M{},
			}}

			err = accounts.Insert(a)
			if err != nil {
				return "json", response, err
			}

			response.Success("U bent successvol geregistreerd.")

		} else {
			response.Error("U heeft al een account.")
		}
	*/

	return "json", response, nil
}
