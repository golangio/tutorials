// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
    "encoding/base64"
    "net/http"
    "strings"
)

type BasicAuth struct {
    Login    string
    Password string
    Realm    string
}

func NewBasicAuth(login, pass string) *BasicAuth {
    return &BasicAuth{Login: login, Password: pass}
}

func (a *BasicAuth) Authenticate(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("WWW-Authenticate", `Basic realm="`+a.Realm+`"`)
    http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (a *BasicAuth) BasicAuthHandler(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !a.ValidAuth(r) {
            a.Authenticate(w, r)
        } else {
            h.ServeHTTP(w, r)
        }
    })
}

func (a *BasicAuth) ValidAuth(r *http.Request) bool {
    s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
    if len(s) != 2 || s[0] != "Basic" {
        return false
    }

    b, err := base64.StdEncoding.DecodeString(s[1])
        if err != nil {
            return false
        }

        parts := strings.SplitN(string(b), ":", 2)
        if len(parts) != 2 {
            return false
        }

        if a.Login == parts[0] && a.Password == parts[1] {
            return true
        }

        return false
}

func main() {
    auth := NewBasicAuth("foo", "secret")
    handler := auth.BasicAuthHandler(http.FileServer(http.Dir("/")))
    http.ListenAndServe("localhost:8080", handler)
}
