package login

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/security/principal"
	"github.com/thrisp/security/user"
)

type Tuser struct {
	principal.Identity
	username string
	password string
	active   bool
}

func (u *Tuser) Authenticate(s string) error {
	return nil
}

func (u *Tuser) Authenticated() bool {
	return true
}

func (u *Tuser) Active() bool {
	return u.active
}

func (u *Tuser) Anonymous() bool {
	return false
}

func (u *Tuser) Id() string {
	return u.username
}

func (u *Tuser) Confirm() {}

func (u *Tuser) Confirmed() bool {
	return true
}

func (u *Tuser) Email() string {
	return fmt.Sprintf("%s@test.com", u.username)
}

func (u *Tuser) Token(key string) string {
	if key == "login" {
		return u.Id()
	}
	return ""
}

func (u *Tuser) Update(string, string) error {
	return nil
}

func (u *Tuser) Validate(key string, token string) bool {
	return false
}

var tusers map[string]*Tuser = map[string]*Tuser{
	"User_One": &Tuser{username: "User_One", password: "test"},
	"User_Two": &Tuser{username: "User_Two", password: "test"},
}

func InMemoryUserLoader(s string) user.User {
	if u, ok := tusers[s]; ok {
		return u
	}
	return user.AnonymousUser
}

func basemanager(c ...Configuration) *Manager {
	c = append(c, UserLoader(InMemoryUserLoader))
	l := New(c...)
	return l
}

func testhandler(c flotilla.Ctx) {
	c.Call("serveplain", 200, "ok")
}

func testapp(t *testing.T, name string, m *Manager) *flotilla.App {
	a := flotilla.New(name,
		flotilla.EnvItem(
			"LOGIN_COOKIE_DURATION:xyz",
			"LOGIN_COOKIE_NAME:test_remember_token",
		))
	a.Messaging.Queues["out"] = func(message string) {}
	m.Init(a)
	err := a.Configure()
	if err != nil {
		t.Errorf("Error in app configuration: %s", err.Error())
	}
	return a
}

func TestExtension(t *testing.T) {
	var exists bool = false
	a := testapp(t, "loginExtension", basemanager())
	exp, _ := flotilla.NewExpectation(
		200, "GET", "/test",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				l, _ := c.Call("loginmanager")
				if _, ok := l.(*Manager); ok {
					exists = true
				}
				c.Call("serveplain", 200, "ok")
			}
		},
	)
	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if !exists {
				t.Errorf("[login] extension does not exist")
			}
		},
	)
	flotilla.SimplePerformer(t, a, exp).Perform()
}

func TestRequireLogin(t *testing.T) {
	a := testapp(t, "requireLogin", basemanager())
	a.UseAt(0, RequireLogin)

	exp, _ := flotilla.NewExpectation(
		401, "GET", "/require/login",
		func(t *testing.T) flotilla.Manage {
			return testhandler
		},
	)
	flotilla.SimplePerformer(t, a, exp).Perform()
}

func TestLoginRequired(t *testing.T) {
	a := testapp(t, "loginRequired", basemanager(
		WithSettings(
			"login_url:/custom/login/url",
		),
	))
	exp, _ := flotilla.NewExpectation(
		307, "GET", "/login/required",
		func(t *testing.T) flotilla.Manage {
			return LoginRequired(testhandler)
		},
	)
	flotilla.SimplePerformer(t, a, exp).Perform()
}

func LoginExpectation(boolvar bool, remember bool) flotilla.Expectation {
	exp, _ := flotilla.NewExpectation(
		200, "POST", "/login",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				u := tusers["User_One"]
				l := manager(c)
				l.LoginUser(u, remember)
				if id := l.CurrentUser().Id(); id == u.username {
					boolvar = true
				}
				c.Call("serveplain", 200, "ok")
			}
		},
	)
	setP := []func(t *testing.T, r *httptest.ResponseRecorder){
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if boolvar != true {
				t.Errorf("[login] logged in was not true it was %t", boolvar)
			}
		},
	}
	if remember {
		setP = append(setP,
			func(t *testing.T, r *httptest.ResponseRecorder) {
				if r.HeaderMap["Set-Cookie"][0][:19] != "test_remember_token" {
					t.Errorf("Remember token not set in response set-cookies")
				}
			},
		)
	}
	exp.SetPost(setP...)
	return exp
}

func TestLogin(t *testing.T) {
	a := testapp(t, "Login", basemanager())
	var loggedIn bool = false
	exp, _ := flotilla.NewExpectation(
		200, "GET", "/afterlogin",
		func(t *testing.T) flotilla.Manage {
			return LoginRequired(func(c flotilla.Ctx) {
				l := manager(c)
				usr, _ := c.Call("currentuser")
				usr1 := usr.(*Tuser)
				usr2 := l.CurrentUser()
				if usr1 != usr2 {
					t.Errorf("returned users are not equal [%+v, %+v]", usr1, usr2)
				}
				if usr1.Email() != "User_One@test.com" {
					t.Errorf(`[login] user email expected "User_One@test.com", but is %s`, usr1.Email())
				}
			})
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, true), exp).Perform()
}

func postBody(expected string) func(t *testing.T, r *httptest.ResponseRecorder) {
	return func(t *testing.T, r *httptest.ResponseRecorder) {
		expects := []byte(expected)
		body := r.Body.Bytes()
		if bytes.Compare(body, expects) != 0 {
			t.Errorf("Response expected %s, but was %s", expected, body)
		}

	}
}

func flashTop(c flotilla.Ctx, category, msg string) string {
	fl, _ := c.Call("flasher")
	msgs := fl.(flotilla.Flasher).Write("login-message")
	var ret string
	if len(msgs) > 0 {
		ret = fmt.Sprintf(msg, msgs[0])
	}
	return ret
}

func TestUnauthenticatedHandler(t *testing.T) {
	m := basemanager(
		WithSettings("UNAUTHENTICATED_MESSAGE:test requires log-in"),
		Reloader(
			"unauthenticated",
			func(c flotilla.Ctx) {
				c.Call("serveplain", 419, flashTop(c, "login-message", "unauthenticated: %s"))
			},
		),
	)
	a := testapp(t, "Login", m)
	exp, _ := flotilla.NewExpectation(
		419, "GET", "/login/required/custom/handler",
		func(t *testing.T) flotilla.Manage {
			return LoginRequired(func(c flotilla.Ctx) {
				t.Error("[login] handler has been called, but should not")
			})
		},
	)
	exp.SetPost(
		postBody("unauthenticated: test requires log-in"),
	)

	flotilla.SessionPerformer(t, a, exp).Perform()
}

func TestLogout(t *testing.T) {
	var loggedIn bool = false
	var currentUsr user.User
	a := testapp(t, "Logout", basemanager())
	exp2, _ := flotilla.NewExpectation(
		200,
		"GET",
		"/logout",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				l := manager(c)
				l.LogoutUser()
				currentUsr = l.CurrentUser()
			}
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if currentUsr.Id() != "anonymous" {
				t.Errorf("user should be logged out and anonymous, but was %+v", currentUsr)
			}
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, true), exp2).Perform()
}

func SessionClearExpectation() flotilla.Expectation {
	exp, _ := flotilla.NewExpectation(
		200,
		"GET",
		"/session/clear",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				c.Call("deletesession", "user")
				c.Call("deletesession", "user_token")
				c.Call("deletesession", "_fresh")
			}
		},
	)
	return exp
}

func TestRemember(t *testing.T) {
	var loggedIn bool
	a := testapp(t, "Remember", basemanager())
	exp3, _ := flotilla.NewExpectation(
		200,
		"GET",
		"/after/session/expired/",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				l := manager(c)
				usr := l.CurrentUser()
				if usr.Id() != "User_One" {
					t.Errorf(`User is %+v but should be "User_One"`, usr)
				}
			}
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, true), SessionClearExpectation(), exp3).Perform()
}

func TestForget(t *testing.T) {
	var loggedIn bool
	a := testapp(t, "Forget", basemanager())
	exp3, _ := flotilla.NewExpectation(
		200,
		"GET",
		"/after/session/expired/",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				l := manager(c)
				usr := l.CurrentUser()
				if usr.Id() != "anonymous" {
					t.Errorf(`User is %+v but should be "Anonymous"`, usr)
				}
			}
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, false), SessionClearExpectation(), exp3).Perform()
}

func TestRefresh(t *testing.T) {
	var loggedIn bool
	a := testapp(t, "Refresh", basemanager())
	exp3, _ := flotilla.NewExpectation(
		403,
		"GET",
		"/after/session/clear/refresh/required/",
		func(t *testing.T) flotilla.Manage {
			return RefreshRequired(func(c flotilla.Ctx) {})
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, true), SessionClearExpectation(), exp3).Perform()
}

func TestRefreshHandler(t *testing.T) {
	m := basemanager(
		WithSettings("REFRESH_MESSAGE:test requires reauthentication"),
		Reloader(
			"refresh",
			func(c flotilla.Ctx) {
				c.Call("serveplain", 403, flashTop(c, "login-message", "refresh: %s"))
			},
		),
	)
	a := testapp(t, "RefreshHandler", m)
	exp, _ := flotilla.NewExpectation(
		403, "GET", "/refresh/custom/handler",
		func(t *testing.T) flotilla.Manage {
			return RefreshRequired(func(c flotilla.Ctx) {
				t.Error("[login] handler has been called, but should not")
			})
		},
	)
	exp.SetPost(
		postBody("refresh: test requires reauthentication"),
	)

	flotilla.SessionPerformer(t, a, exp).Perform()
}

func TestFresh(t *testing.T) {
	var loggedIn bool
	a := testapp(t, "Fresh", basemanager(
		WithSettings(
			"refresh_url:/custom/refresh/url",
		),
	))
	exp2, _ := flotilla.NewExpectation(
		200, "GET", "/modify/refresh",
		func(t *testing.T) flotilla.Manage {
			return RefreshRequired(func(c flotilla.Ctx) {
				f, _ := c.Call("getsession", "_fresh")
				c.Call("setsession", "_fresh", (f.(int64) + 1000000))
			})
		},
	)
	exp3, _ := flotilla.NewExpectation(
		307, "GET", "/refresh/required",
		func(t *testing.T) flotilla.Manage {
			return RefreshRequired(func(c flotilla.Ctx) {
				t.Error("[login] handler has been called, but should not")
			})
		},
	)

	flotilla.SessionPerformer(t, a, LoginExpectation(loggedIn, true), exp2, exp3).Perform()
}
