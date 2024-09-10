package service

import (
	"GoJwt/internal/repository"
	"log"
)

type MailService interface {
	SendUserWarning(guid string) error
	Close() error
}

type MailServiceImpl struct {
	userRepo repository.UserRepository
}

func NewMailServiceImpl() (*MailServiceImpl, error) {
	userRepository, err := repository.NewUserRepositoryImpl()
	if err != nil {
		return nil, err
	}
	return &MailServiceImpl{userRepo: userRepository}, nil
}

func (m *MailServiceImpl) SendUserWarning(guid string) error {
	email, err := m.userRepo.GetEmailByGUID(guid)
	if err != nil {
		return err
	}
	log.Printf("user %s has chanched ip, warning message sended to %s", guid, email)
	return nil
}

func (m *MailServiceImpl) Close() error {
	return m.userRepo.Close()
}
