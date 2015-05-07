package security

import "github.com/thrisp/flotilla"

func getLogin(f flotilla.Ctx) {}

func postLogin(f flotilla.Ctx) {}

//func getSendLogin(f flotilla.Ctx) {}

//func postSendLogin(f flotilla.Ctx) {}

//func tokenLogin(f flotilla.Ctx) {}

func getLogout(f flotilla.Ctx) {}

//func getRegister(f flotilla.Ctx) {}

//func postRegister(f flotilla.Ctx) {}

//func getForgotPassword(f flotilla.Ctx) {}

//func postForgotPassword(f flotilla.Ctx) {}

//func getResetPassword(f flotilla.Ctx) {}

//func postResetPassword(f flotilla.Ctx) {}

//func getChangePassword(f flotilla.Ctx) {}

//func postChangePassword(f flotilla.Ctx) {}

func makeBlueprint(m *Manager) *flotilla.Blueprint {
	bp := flotilla.NewBlueprint("/")

	bp.GET(m.Setting("logout_url"), getLogout)
	passwordless := m.BoolSetting("passwordless")

	if !passwordless {
		bp.GET(m.Setting("login_url"), getLogin)
		bp.POST(m.Setting("login_url"), postLogin)
	}

	//if !passwordless {
	//	bp.GET(m.Setting("login_url"), getSendLogin)
	///	bp.POST(m.Setting("login_url"), postSendLogin)
	//	passwordlessurl := fmt.Sprint("%s/:token", m.Setting("login_url"))
	//	bp.GET(passwordlessurl, tokenLogin)
	//}

	//if m.BoolSetting("registerable") {
	//	bp.GET(m.Setting("register_url"), getRegister)
	//	bp.POST(m.Setting("register_url"), postRegister)
	//}

	//if m.BoolSetting("recoverable") {
	//	bp.GET(m.Setting("forgot_url"), getForgotPassword)
	//	bp.POST(m.Setting("forgot_url"), postForgotPassword)
	//	reseturl := fmt.Sprint("%s/:token", m.Setting("forgot_url"))
	//	bp.GET(reseturl, getResetPassword)
	//	bp.POST(reseturl, postResetPassword)
	//}

	//if m.BoolSetting("changeable") {
	//	bp.GET(m.Setting("change_url"), getChangePassword)
	//	bp.POST(m.Setting("change_url"), postChangePassword)
	//}

	//if m.BoolSetting("confirmable") {
	//getConfirmation
	//postConfirmation
	//confirmurl := fmt.Sprint("%s/:token", m.Setting("confirm_url"))
	//getConfirmEmail
	//postConfirmEmail
	//}
	//fmt.Printf("%+v\n", bp)
	return bp
}
