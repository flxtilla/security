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

func templateMacro(f Form) func(flotilla.Ctx) template.HTML {
	return func(c flotilla.Ctx) template.HTML {
		prev, _ := c.Call("get", f.Tag())
		if prev != nil {
			return prev.(Form).Render()
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

func LoginForm(s *Manager) Form {
	return s.NewForm(
		"login",
		CheckUserPassword,
		UserName(s, "user-name"),
		PassWord("user-pass", `placeholder="password"`),
		fork.BooleanField("rememberme", "Remember Me", false),
	)
}

func PasswordlessForm(s *Manager) Form {
	return s.NewForm(
		"passwordless",
		CheckForm,
		UserName(s, "user-name"),
		fork.BooleanField("rememberme", "Remember Me", false),
	)
}

func SendResetForm(s *Manager) Form {
	return s.NewForm(
		"send_reset",
		CheckForm,
		UserName(s, "user-name"),
	)
}

func ResetPasswordForm(s *Manager) Form {
	return s.NewForm(
		"reset",
		CheckPasswords,
		UserName(s, "user-name"),
		confirmOne,
		confirmTwo,
		LeasedToken(s, "token:reset"),
	)
}

func ChangePasswordForm(s *Manager) Form {
	return s.NewForm(
		"change",
		CheckPasswords,
		confirmOne,
		confirmTwo,
	)
}

func RegisterForm(s *Manager) Form {
	return s.NewForm(
		"register",
		CheckPasswords,
		UserName(s, "user-name"),
		confirmOne,
		confirmTwo,
	)
}

func SendConfirmForm(s *Manager) Form {
	return s.NewForm(
		"send_confirm",
		CheckForm,
		UserName(s, "user-name"),
	)
}

func ConfirmUserForm(s *Manager) Form {
	return s.NewForm(
		"confirm_user",
		CheckPasswords,
		UserName(s, "user-name"),
		confirmOne,
		confirmTwo,
	)
}
