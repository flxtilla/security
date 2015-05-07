package login

type User interface {
	IsAuthenticated() bool
	IsActive() bool
	IsAnonymous() bool
	GetId() string
}

var AnonymousUser = &anonymoususer{}

type anonymoususer struct{}

func (a anonymoususer) IsAuthenticated() bool {
	return false
}

func (a anonymoususer) IsActive() bool {
	return false
}

func (a anonymoususer) IsAnonymous() bool {
	return true
}

func (a anonymoususer) GetId() string {
	return ""
}
