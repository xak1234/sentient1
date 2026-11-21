// Package canary creates Thinkst Canarytokens (canarytokens.org, free): fake
// credentials and URLs that email you when someone uses them, even after the
// data has left your PC.
package canary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xak1234/sentient1/internal/config"
)

// Endpoint is the public canarytokens.org API base (it lives under an opaque path).
var Endpoint = "https://canarytokens.org/d3aece8093b71007b5ccfedad91ebb11"

type response struct {
	Token              string `json:"token"`
	AuthToken          string `json:"auth_token"`
	TokenURL           string `json:"token_url"`
	Hostname           string `json:"hostname"`
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
	Region             string `json:"region"`
	Error              any    `json:"error"`
	ErrorMessage       string `json:"error_message"`
}

// Create makes a token of kind "aws_keys" or "web". The memo is shown in the
// alert email; it must not contain anything identifying.
func Create(ctx context.Context, kind, email, memo, baitID string) (config.CanaryToken, error) {
	body, _ := json.Marshal(map[string]string{"token_type": kind, "email": email, "memo": memo})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(Endpoint, "/")+"/generate", bytes.NewReader(body))
	if err != nil {
		return config.CanaryToken{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "a-better-antivirus")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return config.CanaryToken{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return config.CanaryToken{}, fmt.Errorf("canarytokens.org: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if r.ErrorMessage != "" || (r.Error != nil && fmt.Sprint(r.Error) != "" && fmt.Sprint(r.Error) != "<nil>") {
		return config.CanaryToken{}, fmt.Errorf("canarytokens.org: %s", firstNonEmpty(r.ErrorMessage, fmt.Sprint(r.Error)))
	}
	if r.Token == "" {
		return config.CanaryToken{}, fmt.Errorf("canarytokens.org: unexpected response (HTTP %d)", resp.StatusCode)
	}
	t := config.CanaryToken{
		Kind: kind, Token: r.Token, AuthToken: r.AuthToken, BaitID: baitID,
		ManageURL: fmt.Sprintf("https://canarytokens.org/nest/manage/%s/%s", r.AuthToken, r.Token),
		Data:      map[string]string{},
	}
	switch kind {
	case "aws_keys":
		if r.AWSAccessKeyID == "" {
			return config.CanaryToken{}, fmt.Errorf("canarytokens.org returned no AWS key")
		}
		t.Data["id"], t.Data["secret"], t.Data["region"] = r.AWSAccessKeyID, r.AWSSecretAccessKey, r.Region
	case "web":
		t.Data["url"] = r.TokenURL
	}
	return t, nil
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
