package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/paths"
)

// Secrets hold credentials for phone alerts and canary tokens. The file is
// DPAPI-encrypted (machine scope) and ACL'd to SYSTEM + Administrators, so
// malware running as the user can't read your webhook or SMTP password.
type Secrets struct {
	Phone  PhoneConfig  `json:"phone"`
	Canary CanaryConfig `json:"canary"`
}

type PhoneConfig struct {
	Kind     string         `json:"kind"` // "" | ntfy | pushover | discord | email
	Ntfy     NtfyConfig     `json:"ntfy,omitempty"`
	Pushover PushoverConfig `json:"pushover,omitempty"`
	Discord  DiscordConfig  `json:"discord,omitempty"`
	Email    EmailConfig    `json:"email,omitempty"`
}

type NtfyConfig struct {
	Server string `json:"server"` // default https://ntfy.sh
	Topic  string `json:"topic"`
	Token  string `json:"token,omitempty"`
}

type PushoverConfig struct {
	AppToken string `json:"appToken"`
	UserKey  string `json:"userKey"`
}

type DiscordConfig struct {
	WebhookURL string `json:"webhookUrl"`
}

type EmailConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	From        string `json:"from"`
	To          string `json:"to"`
	ImplicitTLS bool   `json:"implicitTls"` // port 465 style
}

type CanaryConfig struct {
	Email  string        `json:"email,omitempty"`
	Tokens []CanaryToken `json:"tokens,omitempty"`
}

type CanaryToken struct {
	Kind      string `json:"kind"` // aws_keys | web
	Token     string `json:"token"`
	AuthToken string `json:"authToken"`
	ManageURL string `json:"manageUrl"`
	BaitID    string `json:"baitId"`
	// Kind-specific payload (access key id/secret/region, or URL).
	Data map[string]string `json:"data"`
}

func (p PhoneConfig) Enabled() bool { return p.Kind != "" }

func (p PhoneConfig) Describe() string {
	switch p.Kind {
	case "ntfy":
		srv := p.Ntfy.Server
		if srv == "" {
			srv = "https://ntfy.sh"
		}
		return "ntfy (" + strings.TrimSuffix(srv, "/") + "/" + mask(p.Ntfy.Topic) + ")"
	case "pushover":
		return "Pushover"
	case "discord":
		return "Discord webhook"
	case "email":
		return "Email to " + p.Email.To
	}
	return "off"
}

func mask(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func LoadSecrets() (*Secrets, error) {
	b, err := os.ReadFile(paths.SecretsFile())
	if errors.Is(err, os.ErrNotExist) {
		return &Secrets{}, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	plain, err := unprotect(raw)
	if err != nil {
		return nil, err
	}
	s := &Secrets{}
	return s, json.Unmarshal(plain, s)
}

func SaveSecrets(s *Secrets) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(paths.SecretsFile(), []byte(base64.StdEncoding.EncodeToString(enc))); err != nil {
		return err
	}
	// SYSTEM + Administrators only, no inheritance from the (user-readable) data dir.
	return SetSDDL(paths.SecretsFile(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
}

// SetSDDL applies a protected DACL from SDDL to a file or directory.
func SetSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

const cryptprotectLocalMachine = 0x4

func protect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		b = []byte("{}")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, cryptprotectLocalMachine|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return []byte("{}"), nil
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
