package user

type UserDataStore interface {
	Get(string) User
	Put(User) (User, error)
	Delete(User) error
}
