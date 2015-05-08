package security

import (
	"crypto/md5"
	"fmt"

	"github.com/thrisp/flotilla"

	"github.com/thrisp/security/login"
	"github.com/thrisp/security/principal"
)

var defaultsettings map[string]string = map[string]string{
	"BLUEPRINT_PREFIX":           "",
	"FLASH_MESSAGES":             "t",
	"LOGIN_URL":                  "/login",
	"LOGOUT_URL":                 "/logout",
	"REGISTER_URL":               "/register",
	"RESET_URL":                  "/reset",
	"CHANGE_URL":                 "/change",
	"CONFIRM_URL":                "/confirm",
	"FORGOT_PASSWORD_TEMPLATE":   "security/forgot_password.html",
	"LOGIN_USER_TEMPLATE":        "security/login_user.html",
	"REGISTER_USER_TEMPLATE":     "security/register_user.html",
	"RESET_PASSWORD_TEMPLATE":    "security/reset_password.html",
	"CHANGE_PASSWORD_TEMPLATE":   "security/change_password.html",
	"SEND_CONFIRMATION_TEMPLATE": "security/send_confirmation.html",
	"SEND_LOGIN_TEMPLATE":        "security/send_login.html",
	"CONFIRMABLE":                "f",
	"REGISTERABLE":               "f",
	"RECOVERABLE":                "f",
	"TRACKABLE":                  "f",
	"PASSWORDLESS":               "f",
	"CHANGEABLE":                 "f",
	"CONFIRM_SALT":               "confirm-salt",
	"RESET_SALT":                 "reset-salt",
	"LOGIN_SALT":                 "login-salt",
	"CHANGE_SALT":                "change-salt",
}

var defaultmessages map[string]msg = map[string]msg{
	"unauthorized":                  Msg("You do not have permission to view this resource.", "error"),
	"confirm_registration":          Msg("Thank you. Confirmation instructions have been sent to %(email)s.", "success"),
	"email_confirmed":               Msg("Thank you. Your email has been confirmed.", "success"),
	"already_confirmed":             Msg("Your email has already been confirmed.", "info"),
	"invalid_confirmation_token":    Msg("Invalid confirmation token.", "error"),
	"email_already_associated":      Msg("%(email)s is already associated with an account.", "error"),
	"password_mismatch":             Msg("Password does not match", "error"),
	"retype_password_mismatch":      Msg("Passwords do not match", "error"),
	"invalid_redirect":              Msg("Redirections outside the domain are forbidden", "error"),
	"password_reset_request":        Msg("Instructions to reset your password have been sent to %(email)s.", "info"),
	"password_reset_expired":        Msg("You did not reset your password within %(within)s. New instructions have been sent to %(email)s.", "error"),
	"invalid_reset_password_token":  Msg("Invalid reset password token.", "error"),
	"confirmation_required":         Msg("Email requires confirmation.", "error"),
	"confirmation_request":          Msg("Confirmation instructions have been sent to %(email)s.", "info"),
	"confirmation_expired":          Msg("You did not confirm your email within %(within)s. New instructions to confirm your email have been sent to %(email)s.", "error"),
	"login_expired":                 Msg("You did not login within %(within)s. New instructions to login have been sent to %(email)s.", "error"),
	"login_email_sent":              Msg("Instructions to login have been sent to %(email)s.", "success"),
	"invalid_login_token":           Msg("Invalid login token.", "error"),
	"disabled_account":              Msg("Account is disabled.", "error"),
	"email_not_provided":            Msg("Email not provided", "error"),
	"invalid_email_address":         Msg("Invalid email address", "error"),
	"password_not_provided":         Msg("Password not provided", "error"),
	"password_not_set":              Msg("No password is set for this user", "error"),
	"password_invalid_length":       Msg("Password must be at least 6 characters", "error"),
	"user_does_not_exist":           Msg("Specified user does not exist", "error"),
	"invalid_password":              Msg("Invalid password", "error"),
	"passwordless_login_successful": Msg("You have successfuly logged in.", "success"),
	"password_reset":                Msg("You successfully reset your password and you have been logged in automatically.", "success"),
	"password_is_the_same":          Msg("Your new password must be different than your previous password.", "error"),
	"password_change":               Msg("You successfully changed your password.", "success"),
	"login":                         Msg("Please log in to access this page.", "info"),
	"refresh":                       Msg("Please reauthenticate to access this page.", "info"),
}

type Manager struct {
	App         *flotilla.App
	login       *login.Manager
	principal   *principal.Manager
	signatories map[string]TimeSignatory
	Settings    map[string]string
}

//var securityfxtension map[string]interface{}

//var SecurityFxtension = flotilla.MakeFxtension("fxsecurity", securityfxtension)

func New(c ...Configuration) *Manager {
	s := &Manager{
		login:     login.New(),
		principal: principal.New(),
		Settings:  defaultsettings,
	}

	err := s.Configuration(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-SECURITY] configuration error: %s", err))
	}

	return s
}

func configureSigning(m *Manager, a *flotilla.App) {
	//ss := make(map[string]TimeSignatory)
	//var sigs = []string{"confirm","reset","login","change","token"}
}

func (m *Manager) getSignatory(a *flotilla.App, name string) TimeSignatory {
	secretkey := m.Setting("secret_key")
	salt := m.Setting(fmt.Sprintf("security_%s_salt", name))
	return NewTimeSignatory(secretkey, salt, md5.New) //config option for hash
}

func (m *Manager) Init(a *flotilla.App) {
	m.App = a
	m.login.Init(m.App)
	m.principal.Init(m.App)

	//a.AddFxtensions(SecurityFxtension)

	configureSigning(m, a)

	bp := makeBlueprint(m)
	a.Mount("/", bp)
}
