package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Profile is what the connect page pre-fills. It never holds the password.
type Profile struct {
	URL      string `json:"url"`
	BindDN   string `json:"bindDN"`
	BaseDN   string `json:"baseDN,omitempty"`
	StartTLS bool   `json:"startTLS,omitempty"`
	CAFile   string `json:"caFile,omitempty"`
}

// ProfileOf keeps the UI-settable fields of s.
func ProfileOf(s Settings) Profile {
	return Profile{URL: s.URL, BindDN: s.BindDN, BaseDN: s.BaseDN, StartTLS: s.StartTLS, CAFile: s.CAFile}
}

// DefaultProfilePath is <user config dir>/ldap-console/profile.json.
func DefaultProfilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ldap-console", "profile.json"), nil
}

// LoadProfile returns the saved profile, or a zero Profile if none exists.
func LoadProfile(path string) (Profile, error) {
	var p Profile
	b, err := os.ReadFile(path) // #nosec G304 -- path is our own config file
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// SaveProfile writes p readable only by the current user.
func SaveProfile(path string, p Profile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
