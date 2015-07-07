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

func NewEmailer(m *Manager, templates map[string]string) Emailer {
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

type EmailData map[string]interface{}

func (s *Manager) emailData(email, link string) EmailData {
	return map[string]interface{}{
		"Email": email,
		"Link":  link,
	}
}

func (s *Manager) SendMail(template string, to string, link string) error {
	b, err := s.Emailer.Render(template, s.emailData(to, link))
	if err != nil {
		return err
	}
	return s.Emailer.Send(to, b.Bytes())
}

func (s *Manager) sendNotice(f flotilla.Ctx, form Form, forRoute string, template string) error {
	user, email := formUser(form)
	_, remember := formRememberMe(form)
	tag := form.Tag()
	var ut string
	if user != nil {
		ut = fmt.Sprintf("ut:%s", user.Token(tag))
	}
	rm := fmt.Sprintf("remember:%s", remember)
	sendToken := s.Token(tag, ut, rm)
	link := s.External(f, forRoute, sendToken)
	return s.SendMail(template, email, link)
}

var defaultemailtemplates = map[string]string{
	"passwordless": `Welcome {{ .Email }}!

Please log into your account through the link below:

{{ .Link }}`,
	"send_reset": `Greetings {{ .Email }},
	
Click the link below to reset your password:

{{ .Link }}`,
	"reset_password": `Greetings {{ .Email }},
	
Your password has been changed.

If you did not change your password, click the link below to reset it.

{{ .Link }}
`,
	"send_confirm": `Greetings {{ .Email }},

Please confirm your email through the link below:

{{ .Link }}`,
}
