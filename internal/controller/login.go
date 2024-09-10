package controller

import (
	"GoJwt/internal/service"
	"GoJwt/package/jwt"
	"errors"
	"log"
	"net/http"
)

type LoginController struct {
	mailService  service.MailService
	tokenService *service.TokenServiceImpl
}

func NewLoginController() (*LoginController, error) {
	tokenService, err := service.NewTokenServiceImpl()
	if err != nil {
		return nil, err
	}
	mailService, err := service.NewMailServiceImpl()
	if err != nil {
		return nil, err
	}
	return &LoginController{tokenService: tokenService, mailService: mailService}, nil
}

func (l *LoginController) CreateTokenPair(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	guid := query.Get("guid")
	refresh, err := l.tokenService.GenerateRefreshToken(r.RemoteAddr, guid)
	if err != nil {
		panic(err)
	}
	refreshExp, err := refresh.Payload.ParseAsTime("exp")
	if err != nil {
		panic(err)
	}

	access, err := l.tokenService.GenerateAccessToken(refresh, r.RemoteAddr)
	if err != nil {
		panic(err)
	}

	accessExp, err := access.Payload.ParseAsTime("exp")
	if err != nil {
		panic(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh",
		Value:    refresh.RawToken,
		Expires:  refreshExp.Time,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "access",
		Value:   access.RawToken,
		Expires: accessExp.Time,
	})
	log.Printf("Create token pair for %s", guid)
	w.WriteHeader(http.StatusOK)
}

func (l *LoginController) RefreshAccess(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}
	refresh, err := jwt.NewTokenFromRaw(cookie.Value)
	if err != nil {
		panic(err)
	}
	ip, err := refresh.Payload.ParseAsString("ip")
	if err != nil {
		panic(err)
	}
	typ, err := refresh.Payload.ParseAsString("type")
	if err != nil {
		panic(err)
	}
	if typ != "refresh" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	guid, err := refresh.Payload.ParseAsString("guid")
	if err != nil {
		panic(err)
	}
	if ip != r.RemoteAddr {

		err = l.mailService.SendUserWarning(guid)
		if err != nil {
			panic(err)
		}
	}

	access, err := l.tokenService.GenerateAccessToken(refresh, r.RemoteAddr)
	if err != nil {
		panic(err)
	}
	accessExp, err := access.Payload.ParseAsTime("exp")
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "access",
		Value:   access.RawToken,
		Expires: accessExp.Time,
	})
	log.Printf("Update access token for %s", guid)

	w.WriteHeader(http.StatusOK)
}

func (l *LoginController) Close() error {
	if err := l.tokenService.Close(); err != nil {
		return err
	}
	if err := l.mailService.Close(); err != nil {
		return err
	}

	return nil
}
