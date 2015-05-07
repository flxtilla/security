package security

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thrisp/fork"
)

var defaultForms = map[string]SecurityForm{
	"login_form":              loginForm,
	"passwordless_login_form": passwordlessForm,
	"confirm_register_form":   confirmRegisterForm,
	"register_form":           registerForm,
	"forgot_password_form":    forgotPasswordForm,
	"reset_password_form":     resetPasswordForm,
	"change_password_form":    changePasswordForm,
	"send_confirmation_form":  sendConfirmationForm,
}

type SecurityForm interface {
	fork.Form
}

func NewSecurityForm(fields ...fork.Field) SecurityForm {
	return fork.NewForm(fields...)
}

func confirmablepasswordwidget(options ...string) fork.Widget {
	return fork.NewWidget(fmt.Sprintf(`<fieldset><div class="password-input"><input type="password" name="{{ .Name }}" %s></div><div class="password-input"><input type="password" name="{{ .Name }}-confirm" %s></div></fieldset>`, strings.Join(options, " ")))
}

func ValidPasswords(t *cPassword) error {
	if t.validateable {
		if t.p1 != t.p2 {
			return errors.New("Provided passwords do not match")
		}
	}
	return nil
}

func ConfirmablePassword(name string, options ...string) fork.Field {
	return &cPassword{
		name: name,
		Processor: fork.NewProcessor(
			confirmablepasswordwidget(options...),
			[]interface{}{
				ValidPasswords,
			},
			nil,
		),
	}
}

type cPassword struct {
	name         string
	p1           string
	p2           string
	validateable bool
	fork.Processor
}

func (t *cPassword) New() fork.Field {
	var newfield cPassword = *t
	t.p1, t.p2 = "", ""
	t.validateable = false
	return &newfield
}

func (t *cPassword) Name(name ...string) string {
	if len(name) > 0 {
		t.name = strings.Join(name, "-")
	}
	return t.name
}

func (t *cPassword) Get() *fork.Value {
	return fork.NewValue([]string{t.p1, t.p2})
}

func (t *cPassword) Set(r *http.Request) {
	v1 := t.Filter(t.Name(), r)
	v2 := t.Filter(fmt.Sprintf("%s-confirm", t.Name()), r)
	t.p1 = v1.String()
	t.p2 = v2.String()
	t.validateable = true
}

func (t *cPassword) Validateable() bool {
	return t.validateable
}

var loginForm fork.Form = NewSecurityForm(
	fork.EmailField("email", nil, nil),
	fork.PassWordField("password", nil, nil),
	fork.BooleanField("rememberme", "Remember Me", false),
)

var passwordlessForm = NewSecurityForm(
	fork.EmailField("email", nil, nil),
)

var registerForm = NewSecurityForm(
	fork.EmailField("email", nil, nil),
	ConfirmablePassword("register"),
)

var confirmRegisterForm = NewSecurityForm(
	fork.EmailField("email", nil, nil),
	ConfirmablePassword("confirm-register"),
)

var forgotPasswordForm = NewSecurityForm(
	fork.EmailField("email", nil, nil),
)

var resetPasswordForm = NewSecurityForm(
	ConfirmablePassword("reset"),
)

var changePasswordForm = NewSecurityForm(
	ConfirmablePassword("change"),
)

var sendConfirmationForm = NewSecurityForm(
	fork.EmailField("email", nil, nil),
)
