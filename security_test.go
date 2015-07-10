package security

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/security/principal"
	"github.com/thrisp/security/token"
	"github.com/thrisp/security/user"
)

func testApp(m *Manager) *flotilla.App {
	a := flotilla.New("securityTest", flotilla.Mode("testing", true))
	a.Messaging.Queues["out"] = func(message string) {}
	m.Init(a)
	a.Configure()
	return a
}

func testManager(settings ...string) *Manager {
	settings = append(
		settings,
		"after_login_url:/after/login",
		"after_logout_url:/after/logout",
		"after_passwordless_url:/after/passwordless/request",
		"after_passwordless_token_url:/after/passwordless/login",
		"after_reset_url:/after/password/reset",
		"after_change_url:/after/password/change",
		"after_register_url:/after/register",
		"after_send_confirm_url:/after/send/confirm",
		"after_confirm_user_url:/after/confirm/user",
		"blueprint_prefix:/test",
	)
	return New(
		WithSettings(settings...),
		WithUserDataStore(TDataStore()),
		WithEmailer(TEmailer(defaultemailtemplates)),
	)
}

type testDataStore struct {
	users map[string]*testUser
}

func TDataStore() *testDataStore {
	td := &testDataStore{
		users: make(map[string]*testUser),
	}
	td.New("test-0", "XXXX")
	td.New("test-1", "XXXX")
	for _, u := range td.users {
		u.active = true
		u.confirmed = true
	}
	td.New("test-2", "XXXX")
	td.users["test-2"].active = true
	return td
}

func (td *testDataStore) New(name string, password string) (user.User, error) {
	n := strings.Split(name, "@")[0]
	usr := &testUser{
		Username: n,
		Password: password,
	}
	td.Put(usr)
	return usr, nil
}

func (td *testDataStore) Get(name string) user.User {
	n := strings.Split(name, "@")[0]
	if u, ok := td.users[n]; ok {
		return u
	}
	return user.AnonymousUser
}

var NotATestUser = errors.New("test data store requires a *testUser")

func (td *testDataStore) Put(u user.User) (user.User, error) {
	nu, ok := u.(*testUser)
	if !ok {
		return u, NotATestUser
	}
	td.users[nu.Username] = nu
	return u, nil
}

func (td *testDataStore) Delete(u user.User) error {
	nu, ok := u.(*testUser)
	if !ok {
		return NotATestUser
	}
	delete(td.users, nu.Username)
	return nil
}

type testUser struct {
	Username  string
	Password  string
	Local     string
	active    bool
	confirmed bool
	principal.Identity
}

func (u *testUser) Authenticate(provided string) error {
	if provided == u.Password {
		return nil
	}
	return errors.New("unauthenticated")
}

func (u *testUser) Authenticated() bool {
	return true
}

func (u *testUser) Confirm() {
	u.confirmed = true
}

func (u *testUser) Confirmed() bool {
	return u.confirmed
}

func (u *testUser) Active() bool {
	return u.active
}

func (u *testUser) Anonymous() bool {
	return false
}

func (u *testUser) Email() string {
	return fmt.Sprintf("%s@test.com", u.Username)
}

func (u *testUser) Id() string {
	return u.Username
}

func (u *testUser) Token(key string) string {
	return u.Id()
}

func (u *testUser) Validate(key string, token string) bool {
	if token == u.Id() {
		return true
	}
	return false
}

func (u *testUser) Update(key, value string) error {
	if key == "Local" {
		u.Local = value
		return nil
	}
	if key == "password" {
		u.Password = value
	}
	return errors.New("only Local or Password may be updated")
}

func TestExtension(t *testing.T) {
	var exists bool = false
	a := testApp(New())

	exp, _ := flotilla.NewExpectation(
		200,
		"GET",
		"/security",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				s, _ := c.Call("security")
				if _, ok := s.(*Manager); ok {
					exists = true
				}
				c.Call("serveplain", 200, "ok")
			}
		},
	)

	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			if !exists {
				t.Errorf("[security] extension does not exist")
			}
		},
	)

	flotilla.SimplePerformer(t, a, exp).Perform()
}

func mkPost(r *http.Request, values string) {
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, _ := url.ParseQuery(values)
	r.PostForm = v
}

func mkTokenPost(r *http.Request, values string, token string) {
	mkPost(r, fmt.Sprintf("%s&&signed=%s", values, token))
}

func testHead(t *testing.T, r *httptest.ResponseRecorder, get string, expected string) {
	g := r.HeaderMap.Get(get)
	if g != expected {
		t.Errorf(`ResponseRecorder header map[%s] expected %s, but was %s`, get, expected, g)
	}
}

func testBody(t *testing.T, r *httptest.ResponseRecorder, expected string) {
	if !bytes.Contains(r.Body.Bytes(), []byte(expected)) {
		t.Errorf(`response body did not contain %s:\n\n%s`, expected, r.Body)
	}
}

func LogoutExpectation(url string, redirect string) flotilla.Expectation {
	exp, _ := flotilla.NoTanage(302, "GET", url)
	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", redirect)
		},
	)
	return exp
}

func BaseExpectation() flotilla.Expectation {
	exp, _ := flotilla.NewExpectation(
		303, "GET", "/base",
		func(t *testing.T) flotilla.Manage {
			return LoginRequired(func(c flotilla.Ctx) {
				t.Error("handler called, but should not be called")
			})
		},
	)
	exp.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/login")
		},
	)
	return exp
}

func testFlash(t *testing.T, c flotilla.Ctx, category string, expected string) {
	fl, _ := c.Call("flasher")
	var contains bool
	flashed := fl.(flotilla.Flasher).Write(category)
	for _, flash := range flashed {
		if flash == expected {
			contains = true
		}
	}
	if !contains {
		t.Errorf(`"%s"
		not found with in flash category [%s] containing messages:
		%s`, expected, category, flashed)
	}
}

func testFlashManage(t *testing.T, category string, expected string) flotilla.Manage {
	return func(c flotilla.Ctx) {
		testFlash(t, c, category, expected)
	}
}

func addManage(a *flotilla.App, rt string, m flotilla.Manage) {
	rtm := a.Routes()[rt].Managers
	rtm = append(rtm, m)
	a.Routes()[rt].Managers = rtm
}

func extractSignedToken(b []byte) string {
	var ff [][]byte
	for _, v := range bytes.FieldsFunc(b, func(r rune) bool { return r == '>' }) {
		if bytes.Contains(v, []byte("<input type=")) {
			ff = append(ff, v)
		}
	}
	type fitem struct {
		name  []byte
		value []byte
	}
	var fi []*fitem
	for _, vv := range ff {
		var name, value []byte
		spl := bytes.Fields(vv)
		for _, i := range spl {
			switch {
			case bytes.Contains(i, []byte("name=")):
				name = i
			case bytes.Contains(i, []byte("value=")):
				value = i
			}
		}
		fi = append(fi, &fitem{name: name, value: value})
	}
	for _, vvv := range fi {
		if bytes.Contains(vvv.name, []byte(`name="signed"`)) {
			return string(bytes.Split(vvv.value, []byte(`"`))[1])
		}
	}
	return ""
}

func TestLoginLogout(t *testing.T) {
	a := testApp(testManager())
	var tkn string
	exp0 := BaseExpectation()
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/login")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/login"`)
		},
	)
	exp2, _ := flotilla.NoTanage(200, "POST", "/test/login")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test0@test.com&&user-pass=XXXX", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testBody(t, r, "Specified user does not exist")
		},
	)
	addManage(a, "postLogin", testFlashManage(t, "error", "There was a problem with the information you entered."))
	exp3, _ := flotilla.NoTanage(302, "POST", "/test/login")
	exp3.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-0@test.com&&user-pass=XXXX", tkn)
		},
	)
	exp3.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/after/login")
		},
	)
	exp4, _ := flotilla.NewExpectation(
		200, "GET", "/test/after/login",
		func(t *testing.T) flotilla.Manage {
			return LoginRequired(func(c flotilla.Ctx) {
				testCurrentUser(t, c, "test-0")
			})
		},
	)
	exp5, _ := flotilla.NewExpectation(
		303, "GET", "/anonymous/page/loggedin/user",
		func(t *testing.T) flotilla.Manage {
			return AnonymousRequired(func(c flotilla.Ctx) {})
		},
	)
	exp5.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/after/login")
		},
	)
	exp6 := LogoutExpectation("/test/logout", "/test/after/logout")
	exp7, _ := flotilla.NewExpectation(
		200, "GET", "/anonymous/page",
		func(t *testing.T) flotilla.Manage {
			return AnonymousRequired(func(c flotilla.Ctx) {})
		},
	)
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2, exp3, exp4, exp5, exp6, exp7).Perform()
}

func testCurrentUser(t *testing.T, c flotilla.Ctx, expected string) {
	s := manager(c)
	cu := s.CurrentUser()
	id := cu.Id()
	if id != expected {
		t.Errorf(`current user id was %s, but expected "%s"`, id, expected)
	}
}

func captureEmailerToBuffers(one *bytes.Buffer, two *bytes.Buffer) flotilla.Manage {
	return func(c flotilla.Ctx) {
		s := manager(c)
		emr := s.Emailer.(*testEmailer)
		one.WriteString(emr.last)
		two.WriteString(emr.lastToken)
	}
}

func testBuffer(t *testing.T, b *bytes.Buffer, expected string) {
	if !bytes.Contains(b.Bytes(), []byte(expected)) {
		t.Errorf(`buffer did not contain %s`, expected)
	}
}

func TestPasswordlessLoginLogout(t *testing.T) {
	a := testApp(testManager("passwordless:t"))
	var tkn string
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/p/login")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/p/login"`)
		},
	)
	em, tk := new(bytes.Buffer), new(bytes.Buffer)
	addManage(a, "postSendLogin", captureEmailerToBuffers(em, tk))
	exp2, _ := flotilla.NoTanage(302, "POST", "/test/p/login")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-1@test.com", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testBuffer(t, em, "Please log into your account through the link below:")
		},
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "LOCATION", "/test/after/passwordless/request")
		},
	)
	flotilla.SessionPerformer(t, a, exp1, exp2).Perform()
	exp3, _ := flotilla.NoTanage(302, "GET", fmt.Sprintf("/test/p/login/%s", tk.String()))
	exp3.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "LOCATION", "/test/after/passwordless/login")
		},
	)
	exp4, _ := flotilla.NewExpectation(
		200, "GET", "/test/after/passwordless/login",
		func(t *testing.T) flotilla.Manage {
			return func(c flotilla.Ctx) {
				testCurrentUser(t, c, "test-1")
				testFlash(t, c, "success", "You have been successfully logged in.")
			}
		},
	)
	flotilla.SessionPerformer(t, a, exp3, exp4).Perform()
}

func TestRecover(t *testing.T) {
	a := testApp(testManager("passwordless:f", "recoverable:t"))
	var tkn string
	exp0 := BaseExpectation()
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/send/reset")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/send/reset"`)
		},
	)
	em, tk := new(bytes.Buffer), new(bytes.Buffer)
	addManage(a, "postSendReset", captureEmailerToBuffers(em, tk))
	exp2, _ := flotilla.NoTanage(302, "POST", "/test/send/reset")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-0@test.com", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "LOCATION", "/")
			testBuffer(t, em, "Click the link below to reset your password:")
		},
	)
	addManage(a, "postSendReset", testFlashManage(t, "info", "Instructions to reset your password have been sent to test-0@test.com."))
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2).Perform()
	exp3, _ := flotilla.NoTanage(200, "GET", fmt.Sprintf("/test/reset/%s", tk.String()))
	var sig token.Signatory
	addManage(a, "getResetToken", func(c flotilla.Ctx) { sig = manager(c).signed.(*signed).signatory })
	exp3.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			ctkn, err := sig.Valid(tkn)
			if err != nil {
				t.Error(err.Error())
			}
			if ctkn.Claims["forUser"] != "test-0@test.com" {
				t.Errorf("signed token claims expected forUser=test-0@test.com, but was %s", ctkn.Claims["forUser"])
			}
			testBody(t, r, `<form class="security-form" action="/test/reset"`)
		},
	)
	exp4, _ := flotilla.NoTanage(302, "POST", "/test/reset")
	exp4.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "confirmable-one=1111&confirmable-two=1111", tkn)
		},
	)
	exp4.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "LOCATION", "/test/after/password/reset")
		},
	)
	addManage(a, "postResetPassword", testFlashManage(t, "success", "Your password has been reset successfully and you have been logged in."))
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2, exp3, exp4).Perform()
}

func TestChangePassword(t *testing.T) {
	a := testApp(testManager("passwordless:f", "changeable:t"))
	var tkn string
	exp0 := BaseExpectation()
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/login")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/login"`)
		},
	)
	exp2, _ := flotilla.NoTanage(302, "POST", "/test/login")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-0@test.com&&user-pass=XXXX", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/after/login")
		},
	)
	exp3, _ := flotilla.NoTanage(200, "GET", "/test/change")
	exp3.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/change"`)
		},
	)
	exp4, _ := flotilla.NoTanage(302, "POST", "/test/change")
	exp4.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-0@test.com&confirmable-one=1111&confirmable-two=1111", tkn)
		},
	)
	exp4.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "LOCATION", "/test/after/password/change")
		},
	)
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2, exp3, exp4).Perform()
}

func TestRegister(t *testing.T) {
	a := testApp(testManager("registerable:t"))
	var tkn string
	exp0 := BaseExpectation()
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/register")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/register"`)
		},
	)
	exp2, _ := flotilla.NoTanage(302, "POST", "/test/register")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-3@test.com&confirmable-one=3333&confirmable-two=3333", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/login")
		},
	)
	addManage(a, "postRegister", func(c flotilla.Ctx) {
		s := manager(c)
		usr := s.Get("test-3@test.com")
		if usr.Anonymous() || usr.Email() != "test-3@test.com" {
			t.Errorf(`Newly created and retrieved user email expected "test-3@test.com", but was %s`, usr.Email())
		}
	})
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2).Perform()
}

func TestConfirm(t *testing.T) {
	a := testApp(testManager("confirmable:t"))
	var tkn string
	exp0 := BaseExpectation()
	exp1, _ := flotilla.NoTanage(200, "GET", "/test/send/confirm")
	exp1.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/send/confirm"`)
		},
	)
	em, tk := new(bytes.Buffer), new(bytes.Buffer)
	addManage(a, "postSendConfirm", captureEmailerToBuffers(em, tk))
	exp2, _ := flotilla.NoTanage(302, "POST", "/test/send/confirm")
	exp2.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-2@test.com", tkn)
		},
	)
	exp2.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/after/send/confirm")
			testBuffer(t, em, "Please confirm your email through the link below:")
		},
	)
	flotilla.SessionPerformer(t, a, exp0, exp1, exp2).Perform()
	exp3, _ := flotilla.NoTanage(200, "GET", fmt.Sprintf("/test/confirm/%s", tk.String()))
	exp3.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			tkn = extractSignedToken(r.Body.Bytes())
			testBody(t, r, `<form class="security-form" action="/test/confirm"`)
		},
	)
	exp4, _ := flotilla.NoTanage(302, "POST", "/test/confirm")
	exp4.SetPre(
		func(t *testing.T, r *http.Request) {
			mkTokenPost(r, "user-name=test-2@test.com&confirmable-one=1111&confirmable-two=1111", tkn)
		},
	)
	exp4.SetPost(
		func(t *testing.T, r *httptest.ResponseRecorder) {
			testHead(t, r, "Location", "/test/after/confirm/user")
		},
	)
	addManage(a, "postConfirmUser", testFlashManage(t, "success", "Thank you. Your account email has been confirmed."))
	flotilla.SessionPerformer(t, a, exp3, exp4).Perform()
}
