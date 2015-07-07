package security

import (
	"bytes"
	"net/smtp"
)

func TEmailer(templates map[string]string) Emailer {
	return &testEmailer{
		Auth:      smtp.PlainAuth("", "user@example.com", "password", "mail.example.com"),
		templates: mkEmailTemplates(templates),
	}
}

type testEmailer struct {
	smtp.Auth
	templates EmailTemplates
	last      string
	lastToken string
}

func (te *testEmailer) Render(name string, data map[string]interface{}) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	err := te.templates[name].Execute(b, data)
	return b, err
}

func extractToken(data []byte) string {
	parts := bytes.Fields(data)
	link := parts[len(parts)-1]
	tkn := bytes.Split(link, []byte("/"))
	return string(tkn[len(tkn)-1])
}

func (te *testEmailer) Send(name string, data []byte) error {
	te.last = string(data)
	te.lastToken = extractToken(data)
	return nil
}
