// Package notify delivers alerts: to your phone (ntfy, Pushover, Discord,
// email) from the service, and as a toast + popup on your desktop.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
)

// Message is a channel-neutral alert.
type Message struct {
	Title    string
	Body     string
	Priority int // 1 (low) .. 5 (urgent)
}

// FromAlert builds the phone message for an alert.
func FromAlert(a *alerts.Alert) Message {
	m := Message{Title: a.Title, Priority: 3}
	var b strings.Builder
	if a.Summary != "" {
		b.WriteString(a.Summary + "\n")
	}
	for _, h := range a.Baits {
		fmt.Fprintf(&b, "• %s %s\n", h.Access, h.Name)
	}
	if a.Process != nil {
		fmt.Fprintf(&b, "Process: %s (pid %d)\n", a.ExeName(), a.Process.PID)
		if a.Process.Image != "" {
			fmt.Fprintf(&b, "Path: %s\n", a.Process.Image)
		}
		fmt.Fprintf(&b, "Signature: %s\n", a.Process.Signature)
	}
	for _, r := range a.Actions {
		mark := "✓"
		if !r.OK {
			mark = "✗"
		}
		fmt.Fprintf(&b, "%s %s\n", mark, r.Action)
	}
	if a.Learning {
		b.WriteString("(learning mode: no action taken)\n")
	}
	fmt.Fprintf(&b, "Alert %s", a.ID)
	m.Body = b.String()
	switch a.Tier {
	case config.TierCritical:
		m.Priority = 5
	case config.TierWarn:
		m.Priority = 4
	}
	if a.Test {
		m.Title = "[TEST] " + m.Title
		m.Priority = 3
	}
	return m
}

// Sender sends messages using a dialer that survives isolation: while the PC
// is isolated DNS is blocked, so it falls back to IPs resolved earlier.
type Sender struct {
	Phone config.PhoneConfig
	cache *DialCache
}

func NewSender(p config.PhoneConfig, cache *DialCache) *Sender {
	if cache == nil {
		cache = NewDialCache(nil)
	}
	return &Sender{Phone: p, cache: cache}
}

func (s *Sender) client() *http.Client {
	tr := &http.Transport{
		DialContext:         s.cache.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

// Hosts returns the hostnames this config talks to (for pre-resolving).
func (s *Sender) Hosts() []string {
	switch s.Phone.Kind {
	case "ntfy":
		return []string{hostOf(ntfyServer(s.Phone.Ntfy))}
	case "pushover":
		return []string{"api.pushover.net"}
	case "discord":
		return []string{hostOf(s.Phone.Discord.WebhookURL)}
	case "email":
		return []string{s.Phone.Email.Host}
	}
	return nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func ntfyServer(n config.NtfyConfig) string {
	if n.Server == "" {
		return "https://ntfy.sh"
	}
	return strings.TrimSuffix(n.Server, "/")
}

// Send delivers m via the configured channel.
func (s *Sender) Send(ctx context.Context, m Message) error {
	switch s.Phone.Kind {
	case "":
		return nil
	case "ntfy":
		return s.ntfy(ctx, m)
	case "pushover":
		return s.pushover(ctx, m)
	case "discord":
		return s.discord(ctx, m)
	case "email":
		return s.email(ctx, m)
	}
	return fmt.Errorf("unknown phone channel %q", s.Phone.Kind)
}

func (s *Sender) do(req *http.Request) error {
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", req.URL.Host, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (s *Sender) ntfy(ctx context.Context, m Message) error {
	n := s.Phone.Ntfy
	req, err := http.NewRequestWithContext(ctx, "POST", ntfyServer(n)+"/"+url.PathEscape(n.Topic), strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", asciiHeader(m.Title))
	req.Header.Set("Priority", strconv.Itoa(m.Priority))
	req.Header.Set("Tags", "rotating_light")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	return s.do(req)
}

// asciiHeader keeps header values ASCII (ntfy decodes UTF-8 bodies, not headers).
func asciiHeader(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Sender) pushover(ctx context.Context, m Message) error {
	p := s.Phone.Pushover
	pri := 0
	if m.Priority >= 5 {
		pri = 1
	}
	form := url.Values{"token": {p.AppToken}, "user": {p.UserKey}, "title": {m.Title}, "message": {m.Body}, "priority": {strconv.Itoa(pri)}}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.do(req)
}

func (s *Sender) discord(ctx context.Context, m Message) error {
	color := 0xF5A623
	if m.Priority >= 5 {
		color = 0xE5484D
	}
	payload := map[string]any{
		"username": "sentient1",
		"embeds":   []map[string]any{{"title": m.Title, "description": m.Body, "color": color}},
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", s.Phone.Discord.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req)
}

func (s *Sender) email(ctx context.Context, m Message) error {
	e := s.Phone.Email
	port := e.Port
	if port == 0 {
		port = 587
		if e.ImplicitTLS {
			port = 465
		}
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(port))
	from := e.From
	if from == "" {
		from = e.Username
	}
	msg := "From: SENTIENT1 <" + from + ">\r\nTo: " + e.To + "\r\nSubject: " + m.Title +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.ReplaceAll(m.Body, "\n", "\r\n")

	conn, err := s.cache.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if e.ImplicitTLS {
		conn = tls.Client(conn, &tls.Config{ServerName: e.Host})
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if !e.ImplicitTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%s doesn't offer STARTTLS; refusing to send credentials in clear text", e.Host)
		}
		if err := c.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
			return err
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, to := range strings.Split(e.To, ",") {
		if err := c.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// DialCache remembers resolved IPs so alerts still go out when DNS is blocked.
type DialCache struct {
	mu  sync.Mutex
	ips map[string][]string
}

func NewDialCache(seed map[string][]string) *DialCache {
	c := &DialCache{ips: map[string][]string{}}
	for k, v := range seed {
		c.ips[k] = append([]string(nil), v...)
	}
	return c
}

// Snapshot returns a copy for persisting.
func (c *DialCache) Snapshot() map[string][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string][]string{}
	for k, v := range c.ips {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Refresh resolves hosts now (call while online).
func (c *DialCache) Refresh(ctx context.Context, hosts []string) {
	for _, h := range hosts {
		if h == "" || net.ParseIP(h) != nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(rctx, h)
		cancel()
		if err == nil && len(addrs) > 0 {
			c.mu.Lock()
			c.ips[strings.ToLower(h)] = addrs
			c.mu.Unlock()
		}
	}
}

// DialContext tries normal resolution briefly, then cached IPs.
func (c *DialCache) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 8 * time.Second}
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	addrs, rerr := net.DefaultResolver.LookupHost(rctx, host)
	cancel()
	if rerr == nil && len(addrs) > 0 {
		c.mu.Lock()
		c.ips[strings.ToLower(host)] = addrs
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		addrs = append([]string(nil), c.ips[strings.ToLower(host)]...)
		c.mu.Unlock()
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %s: %v (and no cached address)", host, rerr)
		}
	}
	var lastErr error
	for _, ip := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
