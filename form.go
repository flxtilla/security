package security

import (
	"bytes"
	"fmt"
	"html/template"
	"strconv"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/user"
)

type Form interface {
	Fresh(...fork.Field) Form
	fork.Form
}

type securityform struct {
	m *Manager
	fork.Form
}

func (m *Manager) NewForm(tag string, check interface{}, fields ...fork.Field) Form {
	fields = append(fields, fork.SubmitField("submit", nil, nil), Next(m, "next"))
	return &securityform{
		m:    m,
		Form: fork.NewForm(tag, fork.Checks(check), fork.Fields(fields...)),
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
	if s.m.BoolSetting("form_leased") {
		newform.Form.Fields(LeasedToken(s.m, "token:lease"))
	}
	return &newform
}

func (s *securityform) url() string {
	return s.m.Setting(fmt.Sprintf("%s_url", s.Tag()))
}

func (s *securityform) menu() *bytes.Buffer {
	b := new(bytes.Buffer)
	m := s.m
	var avail []string
	tag := s.Tag()
	if !existsIn(tag, "login", "passwordless") {
		avail = append(avail, m.FmtSetting(`<li><a href="%s">Login</a></li>`, "login_url"))
	}
	if m.BoolSetting("registerable") && !existsIn(tag, "register") {
		avail = append(avail, m.FmtSetting(`<li><a href="%s">Register</a></li>`, "register_url"))
	}
	if m.BoolSetting("recoverable") && !existsIn(tag, "reset", "send_reset") {
		avail = append(avail, m.FmtSetting(`<li><a href="%s">Forgot Password?</a></li>`, "send_reset_url"))
	}
	if m.BoolSetting("confirmable") && !existsIn(tag, "confirm_user", "send_confirm") {
		avail = append(avail, m.FmtSetting(`<li><a href="%s">Confirm Account</a></li>`, "send_confirm_url"))
	}
	if len(avail) > 0 {
		b.WriteString(`<div class="security-form-menu">`)
		b.WriteString(`<ul>`)
		for _, i := range avail {
			b.WriteString(i)
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
	if s.m.BoolSetting("form_menu") {
		b.ReadFrom(s.menu())
	}
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

var PasswordMismatch = SecurityError("Provided passwords do not match")

func CheckPasswords(f Form) (bool, error) {
	if f.Valid(f) {
		p1 := formPassword(f, "confirmable-one")
		p2 := formPassword(f, "confirmable-two")
		if p1 != p2 {
			return false, PasswordMismatch
		}
		return true, nil
	}
	return false, nil
}

func CheckUserPassword(f Form) (bool, error) {
	if f.Valid(f) {
		usr := formUser(f)
		password := formPassword(f, "user-pass")
		if err := usr.Authenticate(password); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func CheckForm(f Form) (bool, error) {
	if f.Valid(f) {
		return true, nil
	}
	return false, nil
}
