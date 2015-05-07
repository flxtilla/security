package security

import (
	"fmt"

	"github.com/thrisp/flotilla"

	"github.com/thrisp/security/login"
	"github.com/thrisp/security/principal"
)

var (
	defaultsettings map[string]string = map[string]string{
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

	defaultmessages map[string]msg = map[string]msg{
		"unauthorized": Msg("You do not have permission to view this resource.", "error"),
	}
)

type Manager struct {
	DataStore
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
		Settings: defaultsettings,
	}

	err := s.Configuration(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-SECURITY] configuration error: %s", err))
	}

	if s.DataStore == nil {
		s.DataStore = &DefaultDataStore{}
	}

	return s
}

func (m *Manager) loginmanager(a *flotilla.App) *login.Manager {
	l := login.New(login.UserLoader(getLoginUserFunc(m.DataStore)))
	l.Init(a)
	return l
}

func (m *Manager) principalmanager(a *flotilla.App) *principal.Manager {
	p := principal.New()
	p.Init(a)
	return p
}

func getSignatory(a *flotilla.App, name string) TimeSignatory {
	//	secret_key = app.config.get('SECRET_KEY')
	//	salt = app.config.get('SECURITY_%s_SALT' % name.upper())
	//	return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)
	return nil
}

func (m *Manager) Init(a *flotilla.App) {
	m.App = a
	m.login = m.loginmanager(m.App)
	m.principal = m.principalmanager(m.App)

	//a.AddFxtensions(SecurityFxtension)

	bp := makeBlueprint(m)
	a.Mount("/", bp)
}
