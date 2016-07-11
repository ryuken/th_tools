package th_tools

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/context"
	"github.com/jmoiron/sqlx"
)

type AccountSQL struct {
    ID          uint
    Email       string
    Password    string
    IsActive    bool   `db:"is_active"`
    DateCreated string `db:"date_created"`
    Token       string
	System      int
}

func (a *AccountSQL) ConvertPassword() {
	// convert password to SHA512
	h := sha512.New()
	io.WriteString(h, a.Password)
	a.Password = fmt.Sprintf("%x", h.Sum(nil))
}

func (a AccountSQL) Validate(w http.ResponseWriter, r *http.Request) {

	response := Response{}
	response.Status = "error"
	response.Body = "Het inloggen is mislukt."

	session := Session{}
	session.New()

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Println(err)
	}

	log.Println(string(body))

	err = json.Unmarshal(body, &a)

	if err != nil {
		log.Println(err)
	}

	system := context.Get(r, "system").(int)

	if system > 0 {

		a.System = system

		session.Token = a.Token

		if valid, _ := session.IsValid(w, r); false == valid {

			db := context.Get(r, "db").(*sqlx.DB)

			var accountSQLID uint
			a.ConvertPassword()

			rows, err := db.Query(`
                SELECT
                    a.id
                FROM
                    auth.accounts a
                INNER JOIN
                    auth.account_roles ar ON a.id = ar.account
                WHERE
                    email = ? AND password = ? AND ar.system = ? AND is_active = 1
            `, a.Email, a.Password, a.System)

			if err != nil {
				log.Println(err)
			}

			defer rows.Close()

			for rows.Next() {

				if err := rows.Scan(&accountSQLID); err != nil {
					log.Println(err)
				}
			}

			if err := rows.Err(); err != nil {
				log.Println(err)
			}

			log.Println(accountSQLID)

			if 0 == accountSQLID {
				response.Body = "U heeft of een verkeerde combinatie van email en wachtwoord ingevoerd of u heeft geen toegang tot dit systeem."
			} else {

				_, err = db.Exec("UPDATE auth.accounts SET last_login_date = CURRENT_TIMESTAMP() WHERE id = ? LIMIT 1", accountSQLID)

				if err != nil {
					log.Println(err)
				}

				session.Account = accountSQLID

				session.Insert(w, r)

				response.Status = "success"
				response.Body = "U bent successvol ingelogd."
			}

		} else {
			response.Body = "U bent al ingelogd."
		}

	} else {
		response.Body = "Er is geen systeem gespecificeerd."
	}

	json.NewEncoder(w).Encode(response)
}

func (a AccountSQL) Logout(w http.ResponseWriter, r *http.Request) {

	response := Response{}
	response.Status = "success"
	response.Body = "U bent successvol uitgelogd."

	session := Session{}
	session.Destroy(w, r)

	json.NewEncoder(w).Encode(response)
}

// Check if AccountSQL is logged in
func (a AccountSQL) Check(w http.ResponseWriter, r *http.Request) {

	response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd of uw sessie is verlopen."

	session := Session{}
	session.New()

	if valid, _ := session.IsValid(w, r); true == valid {

		response.Status = "success"
		response.Body = "U bent nog steeds ingelogd."

		session.Save(w, r)
	}

	json.NewEncoder(w).Encode(response)
}

// Check if AccountSQL is logged in
func (a AccountSQL) CheckPOST(w http.ResponseWriter, r *http.Request) {

	response := Response{}
	response.Status = "error"
	response.Body = "U bent niet ingelogd of uw sessie is verlopen."

	err := r.ParseForm()

	if err != nil {
		log.Println(err)
	}

	system := r.FormValue("system")

	if len(system) > 0 {

		session := Session{}
		session.New()

		if valid, _ := session.IsValid(w, r); true == valid {

			response.Status = "success"
			response.Body = "U bent nog steeds ingelogd."

			session.Save(w, r)
		}

	} else {
		response.Body = "Er is geen systeem gespecificeerd."
	}

	json.NewEncoder(w).Encode(response)
}

func (a AccountSQL) RequireLogin(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session := Session{}
		session.New()

		valid, sess := session.IsValid(w, r)

		if true == valid {
			context.Set(r, "session", sess)
			next.ServeHTTP(w, r)
		} else {

			response := Response{}
			response.Status = "error"
			response.Body = "U bent niet ingelogd of uw sessie is verlopen."

			json.NewEncoder(w).Encode(response)
		}
	})
}

/*
func (a AccountSQL) Register(w http.ResponseWriter, r *http.Request) {

	response := Response{}
	response.Status = "error"
	response.Body = "De registratie is mislukt."

	err := json.NewDecoder(r.Body).Decode(&a)

    if err != nil {
        log.Println(err)
    } else {

		session := Session{}
		session.New()

		if false == session.IsValid(w, r) {

			db := context.Get(r, "db").(*sqlx.DB)

			h := sha512.New()
			io.WriteString(h, a.Password)
			a.Password = fmt.Sprintf("%x", h.Sum(nil))

			result, err := db.Exec("INSERT INTO auth.AccountSQLs VALUES(null, ?, ?, 1, CURRENT_TIMESTAMP(), '')", a.Email, a.Password)

			if err != nil {
				log.Println("AccountSQL SQL:", err)
			} else {

				affected, _ := result.RowsAffected()

				if(affected == 1) {
					response.Status = "success"
					response.Body = "De registratie is successvol voltooid."
				}
			}

		} else {
			response.Body = "U heeft al een AccountSQL."
		}
	}

	json.NewEncoder(w).Encode(response)
}
*/
