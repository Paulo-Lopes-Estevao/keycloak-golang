package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "myclient"
	clientSecret = "6ocaUE5nGg84Ddf9BxKC1GZAZ4QDHIua"
)

func main() {
	provider, err := oidc.NewProvider(context.Background(), "http://localhost:8080/realms/myrealm")
	if err != nil {
		panic(err)
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8081/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "1234567890"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state invalido", http.StatusBadRequest)
			return
		}

		token, err := config.Exchange(context.Background(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Falha ao trocar o token", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Falha ao obter o id_token", http.StatusInternalServerError)
			return
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			http.Error(w, "Falha ao verificar o id_token", http.StatusInternalServerError)
			return
		}

		var claims struct {
			Email    string   `json:"email"`
			Username string   `json:"preferred_username"`
			Roles    []string `json:"roles"`
		}

		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Falha ao obter os claims", http.StatusInternalServerError)
			return
		}



		resp := struct {
			AccessToken *oauth2.Token
			IDToken string
		}{
			token,
			rawIDToken,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Falha ao gerar o json", http.StatusInternalServerError)
			return
		}

		w.Write(data)

	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
