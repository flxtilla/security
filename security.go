package security

import (
	"fmt"

	"github.com/thrisp/flotilla"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/login"
	"github.com/thrisp/security/principal"
	"github.com/thrisp/security/resources"
	"github.com/thrisp/security/token"
	"github.com/thrisp/security/user"
)

type Manager struct {
	user.DataStore
	App       *flotilla.App
	login     *login.Manager
	principal *principal.Manager
	signed    fork.Field
	Settings
	Urls
	Times
	Forms
	Messages
	Signatories
	Emailer
}

func (s *Manager) contextualize(c flotilla.Ctx) *Manager {
	s.login.Reload(c)
	s.principal.LoadIdentity(c)
	return s
}

func manager(c flotilla.Ctx) *Manager {
	s, _ := c.Call("security")
	return s.(*Manager)
}

func mkextension(s *Manager) map[string]interface{} {
	return map[string]interface{}{
		"security": s.contextualize,
	}
}

func (s *Manager) mkfxtension() flotilla.Fxtension {
	return flotilla.MakeFxtension("fxsecurity", mkextension(s))
}

func New(c ...Configuration) *Manager {
	s := &Manager{
		login:     login.New(),
		principal: principal.New(),
		Settings:  defaultSettings,
		Messages:  defaultMessages,
	}

	s.Forms = defaultForms(s)

	err := s.Configuration(c...)

	if s.DataStore == nil {
		s.DataStore = user.DefaultDataStore()
	}

	err = s.login.Configure(login.UserLoader(s.Get))

	if err != nil {
		panic(ConfigurationError(err))
	}

	return s
}

func configureApp(s *Manager, a *flotilla.App) {
	s.App = a
	a.AddFxtensions(s.mkfxtension())
	a.Env.Assets = append(a.Env.Assets, resources.SecurityAsset)
	a.AddCtxProcessors(templateMacros(s.Forms))
	s.Urls = s.NewUrls()
	a.Mount("/", makeBlueprint(s))
}

func (s *Manager) configureUnset() {
	if s.Emailer == nil {
		s.Emailer = NewEmailer(s, defaultemailtemplates)
	}
	s.signed = Signed("signed", s.Signatory("signed"))
	s.Times = NewTimes(s)
}

func (s *Manager) Init(a *flotilla.App) {
	configureApp(s, a)
	s.login.Init(s.App)
	s.principal.Init(s.App)
	s.configureSignatories(securitySignatories...)
	s.configureUnset()
}

func (s *Manager) Flash(f flotilla.Ctx, messages ...string) {
	if s.BoolSetting("flash_messages") {
		category, message := s.fmtMessage(messages...)
		f.Call("flash", category, message)
	}
}

func (s *Manager) LoginUser(u user.User, remember bool, f flotilla.Ctx) {
	s.login.LoginUser(u, remember)
	s.principal.Change(u, f)
}

func (s *Manager) LogoutUser(f flotilla.Ctx) {
	s.login.LogoutUser()
	s.principal.Change(user.AnonymousUser, f)
}

func (s *Manager) CurrentUser() user.User {
	return s.login.CurrentUser()
}

func (s *Manager) ManagerLogin() string {
	if s.Passwordless() {
		return "PASSWORDLESS_URL"
	}
	return "LOGIN_URL"
}

func (s *Manager) Passwordless() bool {
	return s.BoolSetting("passwordless")
}

type Signatories map[string]token.Signatory

func (s *Manager) Signatory(key string) token.Signatory {
	if sig, ok := s.Signatories[key]; ok {
		return sig
	}
	return s.DefaultSignatory()
}

func (s *Manager) DefaultSignatory() token.Signatory {
	if sig, ok := s.Signatories["default"]; ok {
		return sig
	}
	return s.newSignatory("default", "HS256")
}

var securitySignatories []string = []string{
	"default", "passwordless", "send_confirm", "send_reset", "signed",
}

func (s *Manager) configureSignatories(sigs ...string) {
	ss := make(Signatories)
	for _, sig := range sigs {
		ss[sig] = s.newSignatory(sig, s.Setting("signing_method"))
	}
	s.Signatories = ss
}

func (s *Manager) secret(forSalt string) string {
	key := s.Setting("secret_key")
	salt := s.Setting(fmt.Sprintf("%s_salt", forSalt))
	return fmt.Sprintf("%s%s", salt, key)
}

func (s *Manager) newSignatory(name, method string) token.Signatory {
	return token.NewSignatory(
		name,
		s.Setting("timestamp_format"),
		s.Setting("signatory_encryption_key"),
		token.NewSigner(method, s.secret(name)),
	)
}

func (s *Manager) Token(from string, claims ...string) string {
	sig := s.Signatory(from)
	return sig.SignedString(claims...)
}
