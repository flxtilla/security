package security

import (
	"errors"

	"github.com/thrisp/login"
)

type UserDataStore interface {
	Get(string) User
	Put(User) (User, error)
	Delete(User) error
}

func getLoginUserFunc(d DataStore) func(string) login.User {
	return func(s string) login.User {
		return d.Get(s).(login.User)
	}
}

type RoleDataStore interface {
	//CreateRole(...string) error
	//GetRole(string) Role
}

type DataStore interface {
	UserDataStore
	RoleDataStore
}

var NotImplemented = errors.New("[FLOTILLA-SECURITY] Not Implemented")

type DefaultDataStore struct{}

func (t *DefaultDataStore) Get(s string) User {
	return AnonymousUser
}

func (t *DefaultDataStore) Put(User) (User, error) {
	return nil, NotImplemented
}

func (t *DefaultDataStore) Delete(User) error {
	return NotImplemented
}

//func (t *DefaultDataStore) CreateRole(...string) error {
//	return NotImplemented
//}

//func (t *DefaultDataStore) GetRole(string) Role {
//	return nil
//}
