package th_tools

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

type Session struct {
	ID      uint
	Token   string
	Account uint
	Expires string
	Data    string
	hashmap map[string]json.RawMessage
}

func (s *Session) New() {
	s.hashmap = make(map[string]json.RawMessage)
}

func (s *Session) Insert(w http.ResponseWriter, r *http.Request) {

	db := context.Get(r, "db").(*sqlx.DB)

	log.Println("\tSession INSERT")

	utils := Utils{}
	token := utils.String.Generate(10)

	s.Token = token
	// create a date time format as YYYY-MM-DD HH:mm
	const layout = "2006-01-02 15:04"
	// get current time
	t := time.Now()
	// create a duration of 2 hours
	d, _ := time.ParseDuration("2h")
	// add current time with duration
	t = t.Add(d)
	s.Expires = t.Format(layout) // Format current time to YYYY-MM-DD HH:mm

	_, err := db.Exec("INSERT INTO auth.sessions VALUES(null, ?, ?, ?, ?)", s.Token, s.Account, s.Expires, s.Data)

	if err != nil {
		log.Println(err)
	}

	store := context.Get(r, "session-store").(*sessions.CookieStore)

	session, _ := store.Get(r, "session-name")
	// Set some session values.
	session.Values["token"] = token

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60 * 2,
		HttpOnly: true,
	}
	// Save it.
	session.Save(r, w)
}

func (s *Session) IsValid(w http.ResponseWriter, r *http.Request) (bool, Session) {

	db := context.Get(r, "db").(*sqlx.DB)

	// Do garbage collection
	go s.GC(db)

	store := context.Get(r, "session-store").(*sessions.CookieStore)

	session, _ := store.Get(r, "session-name")

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60 * 2,
		HttpOnly: true,
	}

	session.Save(r, w)

	check := false
	temp := Session{}

	if nil != session.Values["token"] {

		//log.Println("Session CHECK token:", session.Values["token"])

		temp.Token, _ = session.Values["token"].(string)

		err := db.Get(&temp, "SELECT * FROM auth.sessions WHERE token = ?", temp.Token)

		if err != nil {
			log.Println("\t", err)
		}

		if temp.ID > 0 {

			*s = temp

			// create a date time format as YYYY-MM-DD HH:mm
			const layout = "2006-01-02 15:04"
			// get current time
			t := time.Now()
			// create a duration of 2 hours
			d, _ := time.ParseDuration("2h")
			// add current time with duration
			t = t.Add(d)
			// update expires in db
			db.Exec("UPDATE auth.sessions SET expires = ? WHERE id = ?", t.Format(layout), temp.ID)

			check = true

			// log.Println("\tUpdated session")
		}
	} else {
		// log.Println("Session CHECK no token")
	}

	return check, temp
}

func (s *Session) Get(r *http.Request, key string) string {

	log.Println("Session GET")
	db := context.Get(r, "db").(*sqlx.DB)
	store := context.Get(r, "session-store").(*sessions.CookieStore)

	session, _ := store.Get(r, "session-name")

	s.Token, _ = session.Values["token"].(string)

	if "" != s.Token {

		var data string
		err := db.Get(&data, "SELECT data FROM auth.sessions WHERE token = ?", s.Token)

		if err != nil {
			log.Println(err)
		}

		err = json.Unmarshal([]byte(data), &s.hashmap)

		if err != nil {
			log.Println("Parsed Error: ", err)
		} else {
			//log.Println("Parsed Data: ", s.hashmap)
		}

		js, err := json.Marshal(s.hashmap)

		if err != nil {
			log.Println("JSON Stringify error:", err)
		}

		s.Data = string(js)

		return string(s.hashmap[key])

	} else {
		return ""
	}
}

func (s *Session) Set(key string, value interface{}) {

	log.Println("Session SET")

	jsValue, err := json.Marshal(value)

	if err != nil {
		log.Println("\tJSON Stringify value error:", err)
	}

	s.hashmap[key] = jsValue

	js, err := json.Marshal(s.hashmap)

	if err != nil {
		log.Println("\tJSON Stringify error:", err)
	}

	s.Data = string(js)
}

func (s *Session) Save(w http.ResponseWriter, r *http.Request) bool {

	store := context.Get(r, "session-store").(*sessions.CookieStore)
	session, _ := store.Get(r, "session-name")

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60 * 2,
		HttpOnly: true,
	}
	// Save it.
	session.Save(r, w)

	if "" != s.Token {

		db := context.Get(r, "db").(*sqlx.DB)

		_, err := db.Exec("UPDATE auth.sessions SET data = ? WHERE token = ?", s.Data, s.Token)

		if err != nil {
			log.Println("\tSession SAVE", err)
		}

		return true

	} else {
		return false
	}
}

// Session DB Garbage Collection
func (s Session) GC(db *sqlx.DB) {
	db.Exec("DELETE FROM auth.sessions WHERE expires < CURRENT_TIMESTAMP()")
}

func (s *Session) Destroy(w http.ResponseWriter, r *http.Request) {

	store := context.Get(r, "session-store").(*sessions.CookieStore)
	session, _ := store.Get(r, "session-name")

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	// Save it.
	session.Save(r, w)

	if "" != session.Values["token"] {
		db := context.Get(r, "db").(*sqlx.DB)
		db.Exec("DELETE FROM auth.sessions WHERE token = ?", session.Values["token"])
	}
}
