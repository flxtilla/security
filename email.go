package security

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"

	"github.com/thrisp/flotilla"
)

type Emailer interface {
	smtp.Auth
	Render(string, map[string]interface{}) (*bytes.Buffer, error)
	Send(string, []byte) error
}

func defaultAuth(m *Manager) smtp.Auth {
	return smtp.CRAMMD5Auth(
		m.Setting("emailer_username"),
		m.Setting("emailer_password"),
	)
}

func DefaultEmailer(m *Manager, templates map[string]string) Emailer {
	return &emailer{
		Auth:      defaultAuth(m),
		address:   m.Setting("emailer_username"),
		host:      m.Setting("emailer_host"),
		templates: mkEmailTemplates(templates),
	}
}

type emailer struct {
	smtp.Auth
	address   string
	host      string
	templates EmailTemplates
}

func (e *emailer) Render(name string, data map[string]interface{}) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	err := e.templates[name].Execute(b, data)
	return b, err
}

func (e *emailer) Send(to string, msg []byte) error {
	tos := []string{to}
	return smtp.SendMail(e.host, e, e.address, tos, msg)
}

type EmailTemplates map[string]*template.Template

func mkEmailTemplates(m map[string]string) EmailTemplates {
	ret := make(map[string]*template.Template)
	for k, v := range m {
		t := template.New(k)
		tm, err := t.Parse(v)
		if err != nil {
			tm, _ = t.Parse(err.Error())
		}
		ret[k] = tm
	}
	return ret
}

func (s *Manager) emailData(email, link string) map[string]interface{} {
	return map[string]interface{}{
		"Email":       email,
		"Link":        link,
		"Confirmable": s.BoolSetting("confirmable"),
		"Recoverable": s.BoolSetting("recoverable"),
	}
}

func (s *Manager) SendMail(to string, name string, link string) error {
	in := s.emailData(to, link)
	b, err := s.Emailer.Render(name, in)
	err = s.Emailer.Send(to, b.Bytes())
	return err
}

var defaultemailtemplates = map[string]string{
	"send_confirm_instructions": sci,
	"login_instructions":        li,
	"passwordless_instructions": li,
	"send_reset_instructions":   sri,
	"change_password_notice":    rn,
}

const (
	sci = `Greetings {{ .Email }},

Please confirm your email through the link below:

{{ .Link }}`

	li = `Welcome {{ .Email }}!

You can log into your account through the link below:

{{ .Link }}`

	sri = `Greetings {{ .Email }},
	
Click the link below to reset your password:

{{ .Link }}`

	rn = `Greetings {{ .Email }},
	
Your password has been changed.
{{ if .Recoverable }}
If you did not change your password, click the link below to reset it.

{{ .Link }}
{{ end }}`
)

func (s *Manager) sendInstructions(f flotilla.Ctx, form Form, forRoute string) error {
	user := formUser(form)
	to := user.Email()
	_, remember := formRememberMe(form)
	tag := form.Tag()
	sendToken := s.generateToken(tag, string(user.Token(tag)), remember)
	link := s.ExternalUrl(f, forRoute, string(sendToken))
	return s.SendMail(
		to,
		fmt.Sprintf("%s_instructions", tag),
		link,
	)
}

func (s *Manager) sendNotice(f flotilla.Ctx, form Form) error {
	user := formUser(form)
	to := user.Email()
	tag := form.Tag()
	return s.SendMail(
		to,
		fmt.Sprintf("%s_notice", tag),
		"",
	)

}
