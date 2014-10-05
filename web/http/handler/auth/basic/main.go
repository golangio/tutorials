package main

import (
    "encoding/base64"
    "log"
    "net/http"
    "strings"
)

type HttpBasic struct {
    Login    string
    Password string
    Realm    string
}

func NewHttpBasic(login, password string) *HttpBasic {
    return &HttpBasic{Login: login, Password: password}
}

func (hb *HttpBasic) authenticate(w http.ResponseWriter, code int) {
    w.Header().Set("WWW-Authenticate", "Basic realm=\""+hb.Realm+"\"")
    http.Error(w, http.StatusText(code), code)
}

func (hb *HttpBasic) AuthHandler(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        if auth := r.Header["Authorization"]; len(auth) > 0 {
            token := strings.Replace(string(auth[0]), "Basic ", "", 1)
            s, err := base64.StdEncoding.DecodeString(token)
            if err != nil {
                log.Fatal(err)
            }

            if parts := strings.Split(string(s), ":"); len(parts) == 2 {
                if hb.Login == parts[0] && hb.Password == parts[1] {
                    h.ServeHTTP(w, r)
                } else {
                    hb.authenticate(w, 401)
                }
            }
        } else {
            hb.authenticate(w, 401)
        }
    })
}

func main() {
    auth := NewHttpBasic("gopher", "1234")
    handler := auth.AuthHandler(http.FileServer(http.Dir("/")))
    http.ListenAndServe(":8080", handler)
}
