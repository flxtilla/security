package security

import (
	"errors"
	"fmt"
)

var defaultMessages map[string]Message = map[string]Message{
	"form_error":                 Msg("There was a problem with the information you entered.", "error"),
	"unauthorized":               Msg("You do not have permission to view this resource.", "error"),
	"unauthenticated":            Msg("You do not have an authenticated account to view this resource.", "error"),
	"confirm_registration":       Msg("Thank you. Confirmation instructions have been sent to %s.", "success"),
	"registration_error":         Msg("Error in registering user: %s", "error"),
	"registration_success":       Msg("Registration success", "success"),
	"email_confirmed":            Msg("Thank you. Your email has been confirmed.", "success"),
	"already_confirmed":          Msg("Your email has already been confirmed.", "info"),
	"invalid_confirmation_token": Msg("Invalid confirmation token.", "error"),
	"email_already_associated":   Msg("%s is already associated with an account.", "error"),
	"password_mismatch":          Msg("Password does not match", "error"),
	"retype_password_mismatch":   Msg("Passwords do not match", "error"),
	"invalid_redirect":           Msg("Redirections outside the domain are forbidden", "error"),
	"reset_instructions_sent":    Msg("Instructions to reset your password have been sent to %s.", "info"),
	"reset_expired":              Msg("You did not reset your password within %s. New instructions have been sent to %s.", "error"),
	"invalid_reset_token":        Msg("Invalid reset password token.", "error"),
	"confirmation_required":      Msg("Email requires confirmation.", "error"),
	"confirmation_request_sent":  Msg("Confirmation instructions have been sent to %s.", "info"),
	"confirmation_expired":       Msg("You did not confirm your email within %s. New instructions to confirm your email have been sent to %s.", "error"),
	"login_expired":              Msg("You did not login within %s. New instructions to login have been sent to %s.", "error"),
	"login_email_sent":           Msg("Instructions to login have been sent to the provided email address.", "success"),
	"invalid_login_token":        Msg("Invalid login token.", "error"),
	"disabled_account":           Msg("Account is disabled.", "error"),
	"email_not_provided":         Msg("Email not provided", "error"),
	"invalid_email_address":      Msg("Invalid email address", "error"),
	"password_not_provided":      Msg("Password not provided", "error"),
	"password_not_set":           Msg("No password is set for this user", "error"),
	"password_invalid_length":    Msg("Password must be at least 6 characters", "error"),
	"user_does_not_exist":        Msg("Specified user does not exist", "error"),
	"invalid_password":           Msg("Invalid password", "error"),
	"reset_successful":           Msg("Your password has been reset successfully and you have been logged in.", "success"),
	"password_is_the_same":       Msg("Your new password must be different than your previous password.", "error"),
	"password_change":            Msg("You successfully changed your password.", "success"),
	"login":                      Msg("Please log in to access this page.", "info"),
	"refresh":                    Msg("Please reauthenticate to access this page.", "info"),
	"login_successful":           Msg("You have been successfully logged in.", "success"),
	"passwordless_login_success": Msg("You have successfuly logged in.", "success"),
	"logout_successful":          Msg("You have been successfully logged out.", "success"),
}

type Messages map[string]Message

type Message interface {
	Category() string
	String() string
	Error() error
}

type msg [2]string

func (m msg) String() string {
	return m[0]
}

func (m msg) Category() string {
	return m[1]
}

func (m msg) Error() error {
	return errors.New(m[0])
}

func Msg(text string, label string) Message {
	return msg{text, label}
}

func MsgError(s *Manager, ms string) error {
	return s.Message(ms).Error()
}

func (s *Manager) Message(ms string) Message {
	if ret, ok := s.Messages[ms]; ok {
		return ret
	}
	return Msg(fmt.Sprintf(`message "%s" does not exist`, ms), "error")
}

func (s *Manager) fmtMessage(messages ...string) (string, string) {
	pre := s.Message(messages[0])
	var out string
	if len(messages) > 1 {
		out = fmt.Sprintf(pre.String(), messages[1:])
	} else {
		out = pre.String()
	}
	return pre.Category(), out
}
