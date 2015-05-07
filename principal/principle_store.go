package principal

type PrincipalStore interface {
	GetPermission(string) Permission
	AddPermission(string, ...interface{}) error
}
