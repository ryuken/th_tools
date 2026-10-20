package th_tools

import (
	"context"
	"net/http"
)

type contextKey string

// WithValue returns a copy of r that carries value under key, e.g.
// r = th_tools.WithValue(r, "db", db). It replaces gorilla/context.Set.
func WithValue(r *http.Request, key string, value interface{}) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey(key), value))
}

// Value returns the value stored under key by WithValue, or nil.
// It replaces gorilla/context.Get.
func Value(r *http.Request, key string) interface{} {
	return r.Context().Value(contextKey(key))
}
