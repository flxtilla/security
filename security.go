package security

import (
	"crypto/md5"
	"fmt"
	"hash"

	"github.com/thrisp/flotilla"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/login"
	"github.com/thrisp/security/principal"
	"github.com/thrisp/security/resources"
	"github.com/thrisp/security/user"
)

type Manager struct {
	user.DataStore
	App       *flotilla.App
	login     *login.Manager
	principal *principal.Manager
	hshfnc    func() hash.Hash
	xsrf      fork.Field
	Signatories
	Emailer
	Forms
	Settings
	Messages
}

func (s *Manager) contextualize(c flotilla.Ctx) *Manager {
	s.login.Reload(c)
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

	s.login.Configure(login.UserLoader(s.Get))
	s.principal.Configure(principal.UseSession())

	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-SECURITY] configuration error: %s", err))
	}

	return s
}

func configureApp(s *Manager, a *flotilla.App) {
	s.App = a
	a.AddFxtensions(s.mkfxtension())
	a.Env.Assets = append(a.Env.Assets, resources.SecurityAsset)
	a.AddCtxProcessors(templateMacros(s.Forms))
	a.Mount("/", makeBlueprint(s))
}

func (s *Manager) configureUnset() {
	if s.hshfnc == nil {
		s.hshfnc = md5.New
	}
	if s.Emailer == nil {
		s.Emailer = DefaultEmailer(s, defaultemailtemplates)
	}
	if s.BoolSetting("form_xsrf") && s.xsrf == nil {
		s.xsrf = fork.XSRF("x", s.Setting("xsrf-salt"))
	}
}

func (s *Manager) Init(a *flotilla.App) {
	configureApp(s, a)

	s.login.Init(s.App)
	s.principal.Init(s.App)

	s.configureUnset()

	s.configureSignatories(s.App)
}

func (s *Manager) Flash(f flotilla.Ctx, messages ...string) {
	if s.BoolSetting("flash_messages") {
		category, message := s.fmtMessage(messages...)
		f.Call("flash", category, message)
	}
}

func (s *Manager) LoginUser(u user.User, remember bool, f flotilla.Ctx) {
	s.login.LoginUser(u, remember, true)
	s.principal.Change(u)
}

func (s *Manager) LogoutUser() {
	s.login.LogoutUser()
	s.principal.Change(user.AnonymousUser)
}

func (s *Manager) CurrentUser() user.User {
	return s.login.CurrentUser()
}

func (s *Manager) ExternalUrl(f flotilla.Ctx, route string, params ...string) string {
	url, _ := f.Call("urlfor", route, true, params)
	return url.(string)
}

func (s *Manager) ManagerLogin() string {
	if s.BoolSetting("passwordless") {
		return "PASSWORDLESS_URL"
	}
	return "LOGIN_URL"
}
