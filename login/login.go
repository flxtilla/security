package login

import (
	"fmt"
	"time"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/flotilla/session"
	"github.com/thrisp/security/user"
)

type Manager struct {
	s          session.SessionStore
	userloader func(string) user.User
	App        *flotilla.App
	Settings   map[string]string
	Reloaders  map[string]flotilla.Manage
}

var defaultsettings map[string]string = map[string]string{
	"COOKIE_NAME":             "remember_token",
	"COOKIE_DURATION":         "31",
	"COOKIE_PATH":             "/",
	"MESSAGE_CATEGORY":        "login-message",
	"REFERESH_MESSAGE":        "Please reauthenticate to access this page.",
	"FRESH_FOR":               "7200",
	"UNAUTHENTICATED_MESSAGE": "Please log in to access this page",
}

func New(c ...Configuration) *Manager {
	l := &Manager{
		Settings:  defaultsettings,
		Reloaders: make(map[string]flotilla.Manage),
	}
	c = append(c, Reloader("cookie", l.GetRemembered))
	err := l.Configure(c...)
	if err != nil {
		panic(fmt.Sprintf("[login] configuration error: %s", err))
	}

	return l
}

func mkextension(l *Manager) map[string]interface{} {
	return map[string]interface{}{
		"loginmanager": func(c flotilla.Ctx) *Manager { l.Reload(c); return l },
		"currentuser":  func(c flotilla.Ctx) user.User { return currentuser(c) },
	}
}

func (l *Manager) mkfxtension() flotilla.Fxtension {
	return flotilla.MakeFxtension("fxlogin", mkextension(l))
}

func (l *Manager) Init(app *flotilla.App) {
	l.App = app
	app.Configuration = append(app.Configuration,
		flotilla.Extensions(l.mkfxtension()),
		flotilla.CtxProcessor("CurrentUser", currentuser))
	app.Use(l.UpdateRemembered)
}

func (l *Manager) Reload(c flotilla.Ctx) {
	l.s = flotillaSession(c)
	if l.currentusertoken() == "" {
		for _, fn := range l.Reloaders {
			fn(c)
		}
	}
	l.reloaduser()
}

func (l *Manager) currentusertoken() string {
	if uid := l.s.Get("user_token"); uid != nil {
		return uid.(string)
	}
	return ""
}

func currentuser(c flotilla.Ctx) user.User {
	return manager(c).CurrentUser()
}

func (l *Manager) CurrentUser() user.User {
	if usr := l.s.Get("user"); usr == nil {
		l.reloaduser()
	}
	u := l.s.Get("user")
	return u.(user.User)
}

func (l *Manager) LoginUser(u user.User, remember bool) bool {
	l.s.Set("user_token", u.Token("login"))
	l.s.Set("_fresh", time.Now().Unix())
	l.s.Set("user", u)
	if remember {
		l.s.Set("remember", "set")
	}
	return true
}

func (l *Manager) LogoutUser() bool {
	l.s.Delete("user")
	l.s.Delete("user_token")
	l.s.Set("remember", "clear")
	l.s.Delete("_fresh")
	l.reloaduser()
	return true
}

func (l *Manager) LoadUser(userid string) user.User {
	if l.userloader != nil {
		return l.userloader(userid)
	}
	return user.AnonymousUser
}

func (l *Manager) reloaduser() {
	l.loaduser(l.currentusertoken())
}

func (l *Manager) loaduser(userid string) {
	l.s.Set("user", l.LoadUser(userid))
}

func (l *Manager) Unauthenticated(c flotilla.Ctx) {
	c.Call("flash", l.Setting("message_category"), l.Setting("unauthenticated_message"))
	if h, ok := l.Reloaders["unauthenticated"]; ok {
		h(c)
	} else if loginurl := l.Setting("login_url"); loginurl != "" {
		c.Call("redirect", 307, loginurl)
	} else {
		c.Call("status", 401)
	}
}

func manager(c flotilla.Ctx) *Manager {
	l, _ := c.Call("loginmanager")
	return l.(*Manager)
}

// RequireLogin is a flotilla HandlerFunc that checks for authorized user,
// aborting with 401 if unauthenticated.
func RequireLogin(c flotilla.Ctx) {
	l := manager(c)
	if !l.CurrentUser().Authenticated() {
		l.Unauthenticated(c)
	}
}

// LoginRequired wraps a flotilla HandlerFunc to ensure that the current
// user is logged in and authenticated before calling the handlerfunc.
func LoginRequired(h flotilla.Manage) flotilla.Manage {
	return func(c flotilla.Ctx) {
		l := manager(c)
		if l.CurrentUser().Authenticated() {
			h(c)
		} else {
			l.Unauthenticated(c)
		}
	}
}

func (l *Manager) fresh(f int64) bool {
	nw := time.Now().Unix()
	cmp := (nw - f)
	if cmp >= 0 && cmp <= l.Int64Setting("FRESH_FOR") {
		return true
	}
	return false
}

func (l *Manager) NeedsRefresh() bool {
	if freshAt := l.s.Get("_fresh"); freshAt != nil {
		frsh := freshAt.(int64)
		return !l.fresh(frsh)
	}
	return true
}

func (l *Manager) Refresh(c flotilla.Ctx) {
	c.Call("flash", l.Setting("message_category"), l.Setting("refresh_message"))
	if h := l.Reloaders["refresh"]; h != nil {
		h(c)
	} else if refreshurl := l.Setting("refresh_url"); refreshurl != "" {
		c.Call("redirect", 307, refreshurl)
	} else {
		c.Call("status", 403)
	}
}

func RefreshRequired(h flotilla.Manage) flotilla.Manage {
	return func(c flotilla.Ctx) {
		l := manager(c)
		if l.NeedsRefresh() {
			l.Refresh(c)
		} else {
			h(c)
		}
	}
}

func (l *Manager) SetRemembered(c flotilla.Ctx) {
	name := l.Setting("COOKIE_NAME")
	value, _ := c.Call("getsession", "user_token")
	duration := cookieseconds(l.Setting("COOKIE_DURATION"))
	path := l.Setting("COOKIE_PATH")
	_, _ = c.Call("securecookie", name, value.(string), duration, path)
}

func readcookies(c flotilla.Ctx) map[string]string {
	cks, _ := c.Call("readcookies")
	return cks.(map[string]string)
}

func (l *Manager) GetRemembered(c flotilla.Ctx) {
	if cookie, ok := readcookies(c)[l.Setting("COOKIE_NAME")]; ok {
		c.Call("setsession", "user_token", cookie)
		c.Call("deletesession", "_fresh")
	}
}

func (l *Manager) UpdateRemembered(c flotilla.Ctx) {
	c.Next()
	if remember, _ := c.Call("getsession", "remember"); remember != nil {
		switch remember.(string) {
		case "set":
			l.SetRemembered(c)
		case "clear":
			l.ClearRemembered(c)
		}
		c.Call("deletesession", "remember")
	}
}

func (l *Manager) ClearRemembered(c flotilla.Ctx) {
	name, value, path := l.Setting("COOKIE_NAME"), "", l.Setting("COOKIE_PATH")
	c.Call("securecookie", name, value, 0, path)
}

func flotillaSession(c flotilla.Ctx) session.SessionStore {
	s, _ := c.Call("session")
	return s.(session.SessionStore)
}
