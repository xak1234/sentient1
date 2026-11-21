package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
)

func TestNtfyAndDiscord(t *testing.T) {
	var got []*http.Request
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, string(b))
	}))
	defer srv.Close()

	a := &alerts.Alert{ID: "x", Title: "Bait read by evil.exe", Tier: config.TierCritical,
		Baits:   []alerts.BaitHit{{Name: "passwords.txt on the Desktop", Access: "read"}},
		Process: &alerts.Process{PID: 42, Image: `C:\Users\b\AppData\Local\Temp\evil.exe`}}
	a.AddAction(config.ActionFreeze, nil, "")
	m := FromAlert(a)

	s := NewSender(config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Server: srv.URL, Topic: "my-topic", Token: "tk"}}, nil)
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	r := got[0]
	if r.URL.Path != "/my-topic" || r.Header.Get("Priority") != "5" || r.Header.Get("Authorization") != "Bearer tk" ||
		!strings.Contains(bodies[0], "evil.exe") || !strings.Contains(bodies[0], "✓ freeze") {
		t.Fatalf("ntfy request wrong: %v %v %q", r.URL, r.Header, bodies[0])
	}

	s = NewSender(config.PhoneConfig{Kind: "discord", Discord: config.DiscordConfig{WebhookURL: srv.URL + "/api/webhooks/1/abc"}}, nil)
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	json.Unmarshal([]byte(bodies[1]), &payload)
	if emb := payload["embeds"].([]any)[0].(map[string]any); emb["title"] != m.Title {
		t.Fatalf("discord payload: %s", bodies[1])
	}
}

func TestDialCacheFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	// An unresolvable name that's in the cache must still connect.
	c := NewDialCache(map[string][]string{"sentient1-cached.invalid": {"127.0.0.1"}})
	conn, err := c.DialContext(context.Background(), "tcp", "sentient1-cached.invalid:"+port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
