package security

import (
	"fmt"
	"html/template"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/fork"
)

type Forms map[string]Form

func (s Forms) byKey(key string) Form {
	return s[fmt.Sprintf("%s_form", key)]
}

func defaultForms(s *Manager) Forms {
	return Forms{
		"login_form":              LoginForm(s),
		"passwordless_login_form": PasswordlessForm(s),
		"send_reset_form":         SendResetForm(s),
		"reset_password_form":     ResetPasswordForm(s),
		"change_password_form":    ChangePasswordForm(s),
		"register_form":           RegisterForm(s),
		"send_confirm_form":       SendConfirmForm(s),
		"confirm_user_form":       ConfirmUserForm(s),
	}
}

func ctxForm(c flotilla.Ctx, tag string) Form {
	f, err := c.Call("get", tag)
	if f != nil && err == nil {
		return f.(Form)
	}
	return nil
}

func templateMacro(f Form) func(flotilla.Ctx) template.HTML {
	return func(c flotilla.Ctx) template.HTML {
		prev := ctxForm(c, f.Tag())
		if prev != nil {
			prev.SetCheckable(true)
			return prev.Render()
		}
		return f.Fresh().Render()
	}
}

func templateMacros(forms map[string]Form) map[string]interface{} {
	ret := make(map[string]interface{})
	for k, v := range forms {
		ret[k] = templateMacro(v)
	}
	return ret
}

func securityChecks(sc ...interface{}) []interface{} {
	return sc
}

func LoginForm(s *Manager) Form {
	return s.NewForm(
		"login",
		securityChecks(CheckUserPassword),
		UserName(s, "user-name"),
		PassWord("user-pass", `placeholder="password"`),
		fork.BooleanField("rememberme", "Remember Me", false),
	)
}

func PasswordlessForm(s *Manager) Form {
	return s.NewForm(
		"passwordless",
		securityChecks(),
		UserName(s, "user-name"),
		fork.BooleanField("rememberme", "Remember Me", false),
	)
}

func SendResetForm(s *Manager) Form {
	return s.NewForm(
		"send_reset",
		securityChecks(),
		UserName(s, "user-name"),
	)
}

func ResetPasswordForm(s *Manager) Form {
	return s.NewForm(
		"reset",
		securityChecks(CheckPasswords),
		confirmOne,
		confirmTwo,
	)
}

func ChangePasswordForm(s *Manager) Form {
	return s.NewForm(
		"change",
		securityChecks(CheckPasswords),
		UserName(s, "user-name"),
		confirmOne,
		confirmTwo,
	)
}

func RegisterForm(s *Manager) Form {
	return s.NewForm(
		"register",
		securityChecks(CheckPasswords),
		NewUserName(s, "user-name"),
		confirmOne,
		confirmTwo,
	)
}

func SendConfirmForm(s *Manager) Form {
	return s.NewForm(
		"send_confirm",
		securityChecks(),
		UserName(s, "user-name"),
	)
}

func ConfirmUserForm(s *Manager) Form {
	return s.NewForm(
		"confirm_user",
		securityChecks(CheckPasswords),
		UserName(s, "user-name"),
		confirmOne,
		confirmTwo,
	)
}
