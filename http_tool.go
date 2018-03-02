package th_tools

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/nytimes/gziphandler"
	"net"
)

type HttpTool struct {
	Methods map[string]map[string]http.Handler
    Router *mux.Router
}

func (ht *HttpTool) Init() {
    ht.Router = mux.NewRouter()
	ht.Methods = make(map[string]map[string]http.Handler)
}

func (ht *HttpTool) Get(route string, handler http.Handler) {
	if ht.Methods["GET"] == nil {
		ht.Methods["GET"] = make(map[string]http.Handler)
	}

	ht.Methods["GET"][route] = handler
}

func (ht *HttpTool) Post(route string, handler http.Handler) {
	if ht.Methods["POST"] == nil {
		ht.Methods["POST"] = make(map[string]http.Handler)
	}

	ht.Methods["POST"][route] = handler
}

func (ht *HttpTool) Put(route string, handler http.Handler) {
	if ht.Methods["PUT"] == nil {
		ht.Methods["PUT"] = make(map[string]http.Handler)
	}

	ht.Methods["PUT"][route] = handler
}

func (ht *HttpTool) Delete(route string, handler http.Handler) {
	if ht.Methods["DELETE"] == nil {
		ht.Methods["DELETE"] = make(map[string]http.Handler)
	}

	ht.Methods["DELETE"][route] = handler
}

func (ht *HttpTool) Handle(route string, handler http.Handler) {
	ht.Router.Handle(route, handler)
}

func (ht HttpTool) Route(listener net.Listener, logFile io.Writer) {

	for method := range ht.Methods {

		for route := range ht.Methods[method] {

			fmt.Println(method, route)

			if logFile != nil {
				ht.Router.Handle(route, handlers.LoggingHandler(logFile, ht.Methods[method][route])).Methods(method)
			} else {
				ht.Router.Handle(route, ht.Methods[method][route]).Methods(method)
			}
		}
	}

	/*
			cache := func(next http.Handler) http.Handler {
		        fn := func(w http.ResponseWriter, r *http.Request) {
					// 1000 * 60 = 60000 = 60 seconds / 1 minute
					// 1000 * 60 * 60 = 3600000 = 1 hour
					// 1000 * 60 * 60 * 24 = 86400000 = 24 hours / 1 day
					// 1000 * 60 * 60 * 24 * 30 = 2592000000 = 30 days
					w.Header().Set("Cache-control", "public, max-age=86400000")
		            next.ServeHTTP(w, r)
		        }
		        return http.HandlerFunc(fn)
		    }
	*/

	nocache := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// 1000 * 60 = 60000 = 60 seconds / 1 minute
			// 1000 * 60 * 60 = 3600000 = 1 hour
			// 1000 * 60 * 60 * 24 = 86400000 = 24 hours / 1 day
			// 1000 * 60 * 60 * 24 * 30 = 2592000000 = 30 days
			w.Header().Set("Cache-control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires ", "0")
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}

	ht.Router.PathPrefix("/").Handler(nocache(gziphandler.GzipHandler(http.FileServer(http.Dir("./public/")))))
	http.Handle("/", ht.Router)

	log.Println(fmt.Sprintf("Listening"))
	http.Serve(listener, nil)
}
