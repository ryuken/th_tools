package th_tools

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

var store = sessions.NewCookieStore([]byte("something-very-secret"))

func (a *AccountMGO) ConvertPassword() {
	// convert password to SHA512
	h := sha512.New()
	io.WriteString(h, a.Password)
	a.Password = fmt.Sprintf("%x", h.Sum(nil))
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
	a.ConvertPassword()

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

	db := context.Get(r, "mongodb").(*mgo.Session)
	c := db.DB("quran").C("accounts")

	err = c.Find(bson.M{"email": a.Email, "password": a.Password}).One(&a)
	if err != nil {
		return "json", response, err
	}

	config := context.Get(r, "config").([]byte)
	secret := []byte(gjson.GetBytes(config, "secret").String())

	now := time.Now()
	duration, _ := time.ParseDuration("1h")
	expire := now.Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id": a.Id.String(),
		"iat": now,
		"exp": expire,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "json", response, err
	}

	session, err := store.Get(r, "session")
	if err != nil {
		return "json", response, err
	}

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(expire),
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
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return secret, nil
	})

	if err != nil && err.Error() != "Token is expired" {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	return claims, nil
}

func (a AccountMGO) Check(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd."

	var tokenString string
	tokenString = r.URL.Query().Get("access_token")

	session, err := store.Get(r, "session")
	if err != nil {
		return "json", response, err
	}

	if session.Values["access_token"] != nil {
		tokenString = session.Values["access_token"].(string)
	}

	if len(tokenString) > 0 {
		config := context.Get(r, "config").([]byte)
		secret := []byte(gjson.GetBytes(config, "secret").String())

		claims, err := check(secret, tokenString)
		//log.Println(claims)

		if err != nil {
			return "json", response, err
		}

		expire := claims["exp"].(float64)
		tm := time.Unix(int64(expire), 0)
		now := time.Now()

		//log.Println("exp", tm)

		if tm.Before(now) {
			log.Println("expired, generating new token")

			duration, _ := time.ParseDuration("1h")

			claims["iat"] = now
			claims["exp"] = now.Add(duration).Unix()

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

			// Sign and get the complete encoded token as a string using the secret
			tokenString, _ = token.SignedString(secret)

			response.Success(tokenString)
		}

		response.Success(tokenString)

		session.Values["access_token"] = tokenString
		session.Save(r, w)
	}

	return "json", response, nil
}

// TODO cookie based auth
func (a AccountMGO) RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var tokenString string
		tokenString = r.URL.Query().Get("access_token")

		config := context.Get(r, "config").([]byte)
		secret := []byte(gjson.GetBytes(config, "secret").String())

		session, err := store.Get(r, "session")
		if err != nil {
			next.ServeHTTP(w, r)
		}

		if session.Values["access_token"] != nil {
			tokenString = session.Values["access_token"].(string)
		}

		claims, err := check(secret, tokenString)
		if err != nil {
			next.ServeHTTP(w, r)
		}

		expire := claims["exp"].(float64)
		tm := time.Unix(int64(expire), 0)
		now := time.Now()

		if tm.Before(now) {
			response := Response{}

			response.Status = "error"
			response.Body = "U bent niet ingelogd of uw sessie is verlopen."

			json.NewEncoder(w).Encode(response)
		} else {
			next.ServeHTTP(w, r)
		}
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
