package security

import (
	"fmt"
	"strconv"
	"strings"
)

type Settings map[string]string

var defaultSettings map[string]string = map[string]string{
	"BLUEPRINT_PREFIX":           "/",
	"FLASH_MESSAGES":             "t",
	"LOGIN_URL":                  "/login",
	"PASSWORDLESS_URL":           "/p/login",
	"LOGOUT_URL":                 "/logout",
	"REGISTER_URL":               "/register",
	"RESET_URL":                  "/reset",
	"SEND_RESET_URL":             "/send/reset",
	"CHANGE_URL":                 "/change",
	"CONFIRM_URL":                "/confirm",
	"SEND_CONFIRM_URL":           "/send/confirm",
	"FORGOT_PASSWORD_TEMPLATE":   "forgot_password.html",
	"LOGIN_USER_TEMPLATE":        "login_user.html",
	"REGISTER_USER_TEMPLATE":     "register_user.html",
	"RESET_PASSWORD_TEMPLATE":    "reset_password.html",
	"CHANGE_PASSWORD_TEMPLATE":   "change_password.html",
	"SEND_CONFIRMATION_TEMPLATE": "send_confirmation.html",
	"SEND_LOGIN_TEMPLATE":        "send_login.html",
	"CONFIRMABLE":                "f",
	"REGISTERABLE":               "f",
	"RECOVERABLE":                "f",
	"TRACKABLE":                  "f",
	"PASSWORDLESS":               "f",
	"CHANGEABLE":                 "f",
	"DEFAULT_SALT":               "default-salt",
	"PASSWORDLESS_SALT":          "login-salt",
	"SEND_CONFIRM_SALT":          "confirm-salt",
	"SEND_RESET_SALT":            "reset-salt",
	"FORM_XSRF":                  "t",
	"XSRF-SALT":                  "xsrf-salt",
	"LEASED_TOKEN_SALT":          "leased-salt",
	"PASSWORDLESS_DURATION":      "12h",
	"SEND_CONFIRM_DURATION":      "60h",
	"SEND_RESET_DURATION":        "60h",
	"LEASED_TOKEN_DURATION":      "5m",
}

func storekey(key string) string {
	return fmt.Sprintf("SECURITY_%s", strings.ToUpper(key))
}

func (s *Manager) Setting(key string) string {
	if item, ok := s.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := s.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (s *Manager) BoolSetting(key string) bool {
	b, err := strconv.ParseBool(s.Setting(key))
	if err == nil {
		return b
	}
	return false
}

func (s *Manager) BoolSettings(keys ...string) bool {
	for _, key := range keys {
		if s.BoolSetting(key) {
			return true
		}
	}
	return false
}

func (s *Manager) FmtSetting(base, key string) string {
	out := s.Setting(key)
	return fmt.Sprintf(base, out)
}

func (s *Manager) settingByValue(value string) (string, string) {
	for k, v := range s.App.Env.Store {
		if value == v.Value {
			return k, v.Value
		}
	}
	for k, v := range s.Settings {
		if value == v {
			return k, v
		}
	}
	return "", ""
}
