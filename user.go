package security

import (
	"github.com/thrisp/login"
	"github.com/thrisp/principal"
)

type Role interface {
	Name() string
	Allows(*principal.Identity) bool
	Requires(*principal.Identity) bool
}

//type role struct {
//	name string
//	*principal.Permission
//}

//func (r *role) Name() string {
//	return r.name
//}

//var roleAnonymous = &role{
//	name:       "anonymous",
//	Permission: principal.NewPermission("anonymous"),
//}

type User interface {
	login.User
	//Roles() []Role
	//HasRole(string) bool
	//AddRole(string) error
	//RemoveRole(string) error
}

var AnonymousUser = &anonymoususer{AnonymousUser: &login.AnonymousUser{}}

type anonymoususer struct {
	*login.AnonymousUser
}

//func (a *anonymoususer) Roles() []Role {
//	return []Role{roleAnonymous}
//}

//func (a *anonymoususer) HasRole(s string) bool {
//	if s == "anonymous" {
//		return true
//	}
//	return false
//}

//func (a *anonymoususer) AddRole(string) error {
//	return NotImplemented
//}

//func (a *anonymoususer) RemoveRole(string) error {
//	return NotImplemented
//}
