package security

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strconv"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/user"
)

type Form interface {
	Fresh(...fork.Field) Form
	Check() (error, bool)
	fork.Form
}

type SecurityCheck func(Form) (error, bool)

type securityform struct {
	m     *Manager
	check SecurityCheck
	fork.Form
}

func (m *Manager) NewForm(tag string, sc SecurityCheck, fields ...fork.Field) Form {
	fields = append(fields, fork.SubmitField("submit", nil, nil), Next(m, "next"))
	return &securityform{
		m:     m,
		check: sc,
		Form:  fork.NewForm(tag, fields...),
	}
}

func (s *securityform) Fresh(with ...fork.Field) Form {
	var newform securityform = *s
	newform.m = s.m
	newform.Form = s.Form.New()
	if len(with) > 0 {
		newform.Form.Fields(with...)
	}
	if s.m.BoolSetting("form_xsrf") {
		newform.Form.Fields(s.m.xsrf.New())
	}
	return &newform
}

func (s *securityform) Check() (error, bool) {
	return s.check(s)
}

func (s *securityform) url() string {
	return s.m.Setting(fmt.Sprintf("%s_url", s.Tag()))
}

func (s *securityform) menu() *bytes.Buffer {
	b := new(bytes.Buffer)
	m := s.m
	if m.BoolSettings("registerable", "recoverable", "confirmable") {
		b.WriteString(`<div class="security-form-menu">`)
		b.WriteString(`<ul>`)
		if s.Tag() != "login" || s.Tag() != "passwordless" {
			b.WriteString(m.FmtSetting(`<li><a href="%s">Login</a></li>`, "login_url"))
		}
		if m.BoolSetting("registerable") {
			b.WriteString(m.FmtSetting(`<li><a href="%s">Register</a></li>`, "register_url"))
		}
		if m.BoolSetting("recoverable") {
			b.WriteString(m.FmtSetting(`<li><a href="%s">Forgot Password?</a></li>`, "send_reset_url"))
		}
		if m.BoolSetting("confirmable") {
			b.WriteString(m.FmtSetting(`<li><a href="%s">Confirm Account</a></li>`, "send_confirm_url"))
		}
		b.WriteString(`</ul>`)
		b.WriteString(`</div>`)
	}
	return b
}

const formhead = `<form class="security-form" action="%s" method="POST" name="%s">`

func (s *securityform) WrapForm(e *bytes.Buffer) *bytes.Buffer {
	b := new(bytes.Buffer)
	b.Write([]byte(fmt.Sprintf(formhead, s.url(), s.Tag())))
	b.ReadFrom(e)
	b.ReadFrom(s.menu())
	b.Write([]byte("</form>"))
	return b
}

func (s *securityform) Buffer() *bytes.Buffer {
	b := new(bytes.Buffer)
	for _, fd := range s.Fields() {
		fb, err := fd.Bytes(fd)
		if err == nil {
			b.ReadFrom(fb)
		}
	}
	return s.WrapForm(b)
}

func (s *securityform) String() string {
	return s.Buffer().String()
}

func (s *securityform) Render() template.HTML {
	return template.HTML(s.String())
}

func formNewUser(f Form) string {
	v := f.Values()
	if n, ok := v["user-name"]; ok {
		return n.String()
	}
	return ""
}

func formUser(f Form) user.User {
	v := f.Values()
	if u, ok := v["user-name"]; ok {
		return u.Raw.(user.User)
	}
	return user.AnonymousUser
}

func formPassword(f Form, key string) string {
	v := f.Values()
	if ret, ok := v[key]; ok {
		return ret.String()
	}
	return ""
}

func formRememberMe(f Form) (bool, string) {
	var b bool
	var s string = "false"
	v := f.Values()
	if rm, ok := v["rememberme"]; ok {
		b = rm.Bool()
		s = strconv.FormatBool(b)
	}
	return b, s
}

func formNext(f Form) string {
	var next string
	v := f.Values()
	if n, ok := v["next"]; ok {
		next = n.String()
	}
	return next
}

var PasswordMismatch = errors.New("Provided passwords do not match")

func CheckPasswords(f Form) (error, bool) {
	if f.Valid() {
		p1 := formPassword(f, "confirmable-one")
		p2 := formPassword(f, "confirmable-two")
		if p1 != p2 {
			return PasswordMismatch, false
		}
		return nil, true
	}
	return nil, false
}

func CheckUserPassword(f Form) (error, bool) {
	if f.Valid() {
		usr := formUser(f)
		password := formPassword(f, "user-pass")
		if err := usr.Authenticate(password); err != nil {
			return err, false
		}
		return nil, true
	}
	return nil, false
}

func CheckForm(f Form) (error, bool) {
	if f.Valid() {
		return nil, true
	}
	return nil, false
}
