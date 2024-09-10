package repository

import "fmt"

type UserRepository interface {
	GetEmailByGUID(guid string) (string, error)
	Close() error
}

type UserRepositoryImpl struct {
}

func NewUserRepositoryImpl() (*UserRepositoryImpl, error) {
	return &UserRepositoryImpl{}, nil
}

func (u *UserRepositoryImpl) GetEmailByGUID(guid string) (string, error) {
	return fmt.Sprintf("%s@example.com", guid), nil
}

func (u *UserRepositoryImpl) Close() error {
	return nil
}
