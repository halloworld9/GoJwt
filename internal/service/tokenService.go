package service

import (
	"GoJwt/internal/repository"
	"GoJwt/package/jwt"
	"errors"
	"github.com/google/uuid"
	"time"
)

type TokenService interface {
	CheckRefreshToken(token *jwt.Token) (bool, error)
	GenerateRefreshToken(ip, guid string) (*jwt.Token, error)
	GenerateAccessToken(refresh *jwt.Token, ip string) (*jwt.Token, error)
	Close() error
}

type TokenServiceImpl struct {
	repo repository.TokenRepository
}

func NewTokenServiceImpl() (*TokenServiceImpl, error) {
	tokenRepository, err := repository.NewTokenRepository()
	if err != nil {
		return nil, err
	}
	return &TokenServiceImpl{repo: tokenRepository}, nil
}

func (t *TokenServiceImpl) CheckRefreshToken(token *jwt.Token) (bool, error) {
	jti, err := token.Payload.ParseAsString("jti")
	if err != nil {
		return false, err
	}
	return t.repo.CheckToken(jti, token.RawToken)
}

func (t *TokenServiceImpl) GenerateRefreshToken(ip, guid string) (*jwt.Token, error) {
	payload := jwt.Payload{}
	payload["ip"] = ip
	payload["guid"] = guid
	payload["iss"] = "localhost"
	exp := jwt.Time{Time: time.Now().Add(time.Hour * 72)}
	payload["exp"] = exp
	jti := uuid.NewString()
	payload["jti"] = jti
	payload["type"] = "refresh"
	token, err := jwt.NewToken(&payload)
	if err != nil {
		return nil, err
	}
	err = t.repo.AddToken(jti, token.RawToken, &exp)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (t *TokenServiceImpl) GenerateAccessToken(refresh *jwt.Token, ip string) (*jwt.Token, error) {
	valid, err := t.CheckRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("refresh token is invalid")
	}
	payload := jwt.Payload{}
	payload["iss"] = "localhost"
	payload["exp"] = jwt.Time{Time: time.Now().Add(time.Minute * 30)}
	payload["ip"] = ip
	payload["guid"], err = refresh.Payload.ParseAsString("guid")
	if err != nil {
		return nil, err
	}
	payload["jti"], err = refresh.Payload.ParseAsString("jti")
	if err != nil {
		return nil, err
	}
	return jwt.NewToken(&payload)
}

func (t *TokenServiceImpl) Close() error {
	return t.repo.Close()
}
