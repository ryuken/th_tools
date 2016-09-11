package th_tools

import (
	"encoding/json"
	"log"
	"net/http"
)

type AppHandler func(http.ResponseWriter, *http.Request) (string, interface{}, error)

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	format, resp, err := fn(w, r)

	if err != nil {
		log.Println(err)
	}

	if "json" == format {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	} else if "plain" == format {
		w.Write([]byte(resp.(string)))
	}
}
