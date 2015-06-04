package login

import (
	"fmt"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/flotilla/session"
	"github.com/thrisp/security/user"
)

type (
	handlers map[string]flotilla.Manage

	Manager struct {
		s          session.SessionStore
		userloader func(string) user.User
		//tokenloader func(string) user.User
		App      *flotilla.App
		Settings map[string]string
		Handlers map[string]flotilla.Manage
	}
)

var (
	defaultsettings map[string]string = map[string]string{
		"COOKIE_NAME":          "remember_token",
		"COOKIE_DURATION":      "31",
		"COOKIE_PATH":          "/",
		"MESSAGE_CATEGORY":     "message",
		"REFERESH_MESSAGE":     "Please reauthenticate to access this page.",
		"UNAUTHORIZED_MESSAGE": "Please log in to access this page",
	}
)

func New(c ...Configuration) *Manager {
	l := &Manager{
		Settings: defaultsettings,
		Handlers: make(handlers),
	}
	c = append(c, Handler("cookie", l.GetRemembered))
	err := l.Configure(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-LOGIN] configuration error: %s", err))
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

func (l *Manager) reloaders() []flotilla.Manage {
	ret := []flotilla.Manage{}
	for _, rl := range []string{"cookie", "request", "token", "header"} {
		if h, ok := l.Handlers[rl]; ok {
			ret = append(ret, h)
		}
	}
	return ret
}

func (l *Manager) Reload(c flotilla.Ctx) {
	l.s = flotillaSession(c)
	if uid := l.s.Get("user_id"); uid != nil {
		for _, fn := range l.reloaders() {
			fn(c)
		}
	}
}

func (l *Manager) currentuserid() string {
	if uid := l.s.Get("user_id"); uid != nil {
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

func (l *Manager) LoginUser(u user.User, remember bool, fresh bool) bool {
	if !u.Active() {
		return false
	}
	l.s.Set("user_id", u.Id())
	l.s.Set("_fresh", fresh)
	l.s.Set("user", u)
	if remember {
		l.s.Set("remember", "set")
	}
	return true
}

func (l *Manager) LogoutUser() bool {
	l.s.Delete("user")
	l.s.Delete("user_id")
	l.s.Set("remember", "clear")
	l.s.Set("_fresh", false)
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
	l.loaduser(l.currentuserid())
}

func (l *Manager) loaduser(userid string) {
	l.s.Set("user", l.LoadUser(userid))
}

func (l *Manager) Unauthenticated(c flotilla.Ctx) {
	c.Call("flash", l.Setting("message_category"), l.Setting("unauthenticated_message"))
	if h := l.Handlers["unauthenticated"]; h != nil {
		h(c)
	}
	if loginurl := l.Setting("login_url"); loginurl != "" {
		c.Call("redirect", 303, loginurl)
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
	currentuser := l.CurrentUser()
	if !currentuser.Authenticated() {
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

func (l *Manager) NeedsRefresh() bool {
	if fresh := l.s.Get("_fresh"); fresh != nil {
		return !fresh.(bool)
	}
	return true
}

func (l *Manager) Refresh(c flotilla.Ctx) {
	if h := l.Handlers["refresh"]; h != nil {
		h(c)
	} else {
		c.Call("flash", l.Setting("message_category"), l.Setting("refresh_message"))
		if refreshurl := l.Setting("refresh_url"); refreshurl != "" {
			c.Call("redirect", 303, refreshurl)
		} else {
			c.Call("status", 403)
		}
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
	value, _ := c.Call("getsession", "user_id")
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
		c.Call("setsession", "user_id", cookie)
		c.Call("setsession", "_fresh", false)
		l.reloaduser()
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
