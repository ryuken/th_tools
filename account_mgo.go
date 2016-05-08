package th_tools

import (
    "io"
    "fmt"
    "time"
    "errors"
    "net/http"
    "encoding/json"
    "crypto/sha512"

    "github.com/antonholmquist/jason"
    "github.com/gorilla/sessions"
	"github.com/gorilla/context"

    "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
    "gopkg.in/boj/redistore.v1"
)

type System struct {
    Id      bson.ObjectId   `bson:"_id,omitempty" json:"_id"`
    Name    string
}

type AccountSystem struct {
    Role        string
    SystemId    bson.ObjectId   `bson:"systemId"`
    Details     bson.M          `bson:",inline"`
}

type AccountMGO struct {
    Id          bson.ObjectId       `bson:"_id,omitempty" json:"_id"`
    Email       string
    Password    string              `json:"-"`
    IsActive    bool                `bson:"isActive"`
    DateCreated time.Time           `bson:"dateCreated"`
    Token       string              `bson:"resetToken"`
    Systems     []AccountSystem     `bson:"systems"`
}

func (a *AccountMGO) ConvertPassword() {
	// convert password to SHA512
	h := sha512.New()
	io.WriteString(h, a.Password)
	a.Password = fmt.Sprintf("%x", h.Sum(nil))
}

func(a *AccountMGO) Sanitize(values *jason.Object, confirm bool) (error) {

    // TODO actual validation
    email, _ := values.GetString("Email")
    password, _ := values.GetString("Password")
    passwordConfirm, _ := values.GetString("PasswordConfirm")

    a.Email = email

    if true == confirm {
        if password != passwordConfirm {
            return errors.New("Password != PasswordConfirm")
        }
    }

    a.Password = password
    a.ConvertPassword()

    return nil
}

func(a AccountMGO) Validate(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

    response := Response{}
	response.Status = "error"
	response.Body = "Het inloggen is mislukt."

    values, err := jason.NewObjectFromReader(r.Body)
    if err != nil {
        return "json", response, err
    }

    a.Sanitize(values, false)

    db := context.Get(r, "mongodb").(*mgo.Session)
    c := db.DB("auth").C("accounts")

    err = c.Find(bson.M{ "email" : a.Email, "password" : a.Password }).One(&a)
    if err != nil {
        return "json", response, err
    }

    store := context.Get(r, "session-store").(*redistore.RediStore)
    // Get a session.
    session, err := store.Get(r, "session-key")
    if err != nil {
        fmt.Println(err.Error())
    }

    session.Values["account"] = a.Id.Hex()

    if err = session.Save(r, w); err != nil {
        fmt.Printf("Error saving session: %v\n", err)
    }

    response.Success(a)

    return "json", response, nil
}

func check(r *http.Request) bool {
    store := context.Get(r, "session-store").(*redistore.RediStore)
    // Get a session.
    session, err := store.Get(r, "session-key")
    if err != nil {
        fmt.Println(err.Error())
    }

    if session.Values["account"] != nil {
        return true
    }

    return false
}

func (a AccountMGO) Check(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

    response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd."

    if check(r) {
        response.Success("U bent al ingelogd.")
    }

    return "json", response, nil
}

func (a AccountMGO) RequireLogin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        if check(r) {
            next.ServeHTTP(w, r)
        }

        response := Response{}
        response.Status = "error"
        response.Body = "U bent niet ingelogd of uw sessie is verlopen."

        json.NewEncoder(w).Encode(response)
    })
}

func (a AccountMGO) Register(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "De registratie is mislukt."

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
        systems.Find(bson.M{ "name" : context.Get(r, "system").(string) }).One(&s)

        a.Systems = []AccountSystem{AccountSystem{
            Role : "user",
            SystemId : s.Id,
            Details : bson.M{},
        }}

		err = accounts.Insert(a)
        if err != nil {
            return "json", response, err
        }

        response.Success("U bent successvol geregistreerd.")

	} else {
		response.Error("U heeft al een account.")
	}

	return "json", response, nil
}

func (a AccountMGO) Logout(w http.ResponseWriter, r *http.Request) (string, interface{}, error) {

	response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd."

	if true == check(r) {

        store := context.Get(r, "session-store").(*redistore.RediStore)
        // Get a session.
        session, err := store.Get(r, "session-key")
        if err != nil {
            fmt.Println(err.Error())
        }

        session.Options = &sessions.Options{
    		Path:     "/",
    		MaxAge:   -1,
    		HttpOnly: true,
    	}
    	// Save it.
    	session.Save(r, w)

        response.Success("U bent successvol uitgelogd.")
	}

	return "json", response, nil
}
