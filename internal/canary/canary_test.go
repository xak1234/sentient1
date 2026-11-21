package canary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateAWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/generate" || req["token_type"] != "aws_keys" || req["email"] != "me@example.com" {
			http.Error(w, "bad", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok", "auth_token": "auth", "aws_access_key_id": "AKIA123", "aws_secret_access_key": "sec", "region": "us-east-2"})
	}))
	defer srv.Close()
	old := Endpoint
	Endpoint = srv.URL
	defer func() { Endpoint = old }()

	tk, err := Create(context.Background(), "aws_keys", "me@example.com", "memo", "aws")
	if err != nil {
		t.Fatal(err)
	}
	if tk.Data["id"] != "AKIA123" || tk.Data["region"] != "us-east-2" || tk.ManageURL != "https://canarytokens.org/nest/manage/auth/tok" {
		t.Fatalf("%+v", tk)
	}
}

func TestCreateError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"error": 5, "error_message": "Invalid email supplied"})
	}))
	defer srv.Close()
	old := Endpoint
	Endpoint = srv.URL
	defer func() { Endpoint = old }()
	if _, err := Create(context.Background(), "web", "nope", "memo", "x"); err == nil {
		t.Fatal("want error")
	}
}
