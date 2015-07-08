package security

import (
	"fmt"
	"strconv"
	"strings"
)

type Settings map[string]string

var defaultSettings Settings = Settings{
	"BLUEPRINT_PREFIX":           "/",
	"FLASH_MESSAGES":             "t",
	"LOGIN_URL":                  "/login",
	"PASSWORDLESS_URL":           "/p/login",
	"PASSWORDLESS_TOKEN_URL":     "/p/login/:token",
	"LOGOUT_URL":                 "/logout",
	"REGISTER_URL":               "/register",
	"SEND_RESET_URL":             "/send/reset",
	"RESET_TOKEN_URL":            "/reset/:token",
	"RESET_URL":                  "/reset",
	"CHANGE_URL":                 "/change",
	"SEND_CONFIRM_URL":           "/send/confirm",
	"CONFIRM_TOKEN_URL":          "/confirm/:token",
	"CONFIRM_USER_URL":           "/confirm",
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
	"PASSWORDLESS":               "f",
	"CHANGEABLE":                 "f",
	"DEFAULT_SALT":               "default-salt",
	"PASSWORDLESS_SALT":          "login-salt",
	"SEND_CONFIRM_SALT":          "confirm-salt",
	"SEND_RESET_SALT":            "reset-salt",
	"SIGNED_SALT":                "signed-salt",
	"LEASED_TOKEN_DURATION":      "5m",
	"PASSWORDLESS_DURATION":      "12h",
	"SEND_CONFIRM_DURATION":      "60h",
	"RESET_DURATION":             "60h",
	"SEND_RESET_DURATION":        "60h",
	"CHANGE_DURATION":            "60h",
	"FORM_MENU":                  "t",
	"NOTIFY_PASSWORD_CHANGE":     "t",
	"NOTIFY_PASSWORD_RESET":      "t",
	"SIGNING_METHOD":             "HS256",
	"TIMESTAMP_FORMAT":           "Mon Jan _2 15:04:05 MST 2006",
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

func (s *Manager) FmtSetting(base, key string) string {
	out := s.Setting(key)
	return fmt.Sprintf(base, out)
}
