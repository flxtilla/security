package security

import (
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/thrisp/fork"
	"github.com/thrisp/security/token"
	"github.com/thrisp/security/user"
)

type securityName struct {
	name string
}

func (s *securityName) Name() string {
	return s.name
}

func (s *securityName) ReName(rename ...string) string {
	if len(rename) > 0 {
		s.name = strings.Join(rename, "-")
	}
	return s.name
}

func (s *securityName) Copy() *securityName {
	var ret securityName = *s
	return &ret
}

func NewUserName(s *Manager, name string, options ...string) fork.Field {
	//user name exists validater
	return fork.TextField(name, []interface{}{fork.ValidEmail}, nil, options...)
}

func UserName(s *Manager, name string, options ...string) fork.Field {
	return &userName{
		securityName: &securityName{name},
		Processor: fork.NewProcessor(
			userNamewidget(s, options...),
			fork.NewValidater(ValidEmail, s.ValidUserName),
			fork.NewFilterer(),
		),
	}
}

func userNamewidget(s *Manager, options ...string) fork.Widget {
	return fork.NewWidget(
		fmt.Sprintf(
			`<input type="email" name="{{ .Name }}" value="{{ .UserName }}" placeholder="email address" %s>`,
			strings.Join(options, " "),
		))
}

type userName struct {
	*securityName
	UserName string
	user     user.User
	fork.Processor
}

func (u *userName) New(i ...interface{}) fork.Field {
	var newfield userName = *u
	newfield.UserName = ""
	newfield.user = user.AnonymousUser
	newfield.SetValidateable(false)
	return &newfield
}

func (u *userName) Get() *fork.Value {
	return fork.NewValue(u.user)
}

func (u *userName) Set(r *http.Request) {
	v := u.Filter(u.Name(), r)
	u.UserName = v.String()
	u.SetValidateable(true)
}

var InvalidEmail = SecurityError(`Invalid email address: %s`).Out

func ValidEmail(u *userName) error {
	if u.Validateable() {
		_, err := mail.ParseAddress(u.UserName)
		if err != nil {
			return InvalidEmail(err)
		}
	}
	return nil
}

func (s *Manager) ValidUserName(u *userName) error {
	if u.Validateable() {
		if u.UserName == "" {
			return MsgError(s, "email_not_provided")
		}
		usr := s.Get(u.UserName)
		if usr.Anonymous() {
			return MsgError(s, "user_does_not_exist")
		}
		if !usr.Active() {
			return MsgError(s, "disabled_account")
		}
		u.user = usr
	}
	return nil
}

func PassWord(name string, options ...string) fork.Field {
	return fork.PassWordField(name, nil, nil, options...)
}

var confirmOne = PassWord("confirmable-one", `placeholder="password"`)
var confirmTwo = PassWord("confirmable-two", `placeholder="confirm password"`)

type next struct {
	m *Manager
	*securityName
	Url string
	fork.Processor
}

func nextwidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Url }}" %s>`, strings.Join(options, " ")))
}

func Next(s *Manager, name string, options ...string) fork.Field {
	return &next{
		m:            s,
		securityName: &securityName{name},
		Processor: fork.NewProcessor(
			nextwidget(options...),
			fork.NewValidater(),
			fork.NewFilterer(nextfilter),
		),
	}
}

func nextfilter(in string) string {
	if in == "" {
		return "/"
	}
	return in
}

func (n *next) New(i ...interface{}) fork.Field {
	var newfield next = *n
	newfield.Url = ""
	newfield.SetValidateable(false)
	return &newfield
}

func (n *next) Get() *fork.Value {
	return fork.NewValue(n.Url)
}

func (n *next) Set(r *http.Request) {
	var nxturl string
	nxturl = n.Filter(n.Name(), r).String()
	nxturl = n.m.nxtAbsolute(r, nil)
	n.Url = nxturl
	n.SetValidateable(true)
}

type signed struct {
	*securityName
	signatory token.Signatory
	claims    []string
	returned  string
	fork.Processor
}

func tokenWidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<input type="hidden" name="{{ .Name }}" value="{{ .Token }}" %s>`, strings.Join(options, " ")))
}

func Signed(name string, s token.Signatory, options ...string) fork.Field {
	return &signed{
		securityName: &securityName{name},
		signatory:    s,
		Processor: fork.NewProcessor(
			tokenWidget(options...),
			fork.NewValidater(ValidateSigned),
			fork.NewFilterer(),
		),
	}
}

func (s *signed) New(i ...interface{}) fork.Field {
	var newfield signed = *s
	newfield.returned = ""
	newfield.claims = toStr(i)
	newfield.SetValidateable(false)
	return &newfield
}

func toStr(i []interface{}) []string {
	var ret []string
	for _, v := range i {
		if st, ok := v.(string); ok {
			ret = append(ret, st)
		}
	}
	return ret
}

func (s *signed) Get() *fork.Value {
	return fork.NewValue(s.returned)
}

func (s *signed) Set(r *http.Request) {
	s.returned = s.Filter(s.Name(), r).String()
	s.SetValidateable(true)
}

func (s *signed) Token() string {
	return s.signatory.SignedString(s.claims...)
}

var InvalidSignedField = SecurityError("Signed field is invalid: %s").Out

func ValidateSigned(s *signed) error {
	if s.Validateable() {
		if _, err := s.signatory.Valid(s.returned); err != nil {
			//spew.Dump(t, err, s.returned)
			return InvalidSignedField(err.Error())
		}
	}
	return nil
}
