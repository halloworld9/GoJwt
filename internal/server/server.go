package server

import (
	"GoJwt/internal/controller"
	"GoJwt/internal/middleware"
	"log"
	"net/http"
	"os"
)

type Server struct {
	mux             *http.ServeMux
	loginController *controller.LoginController
}

func NewServer() (*Server, error) {
	mux := http.NewServeMux()
	loginController, err := controller.NewLoginController()
	if err != nil {
		return nil, err
	}
	server := &Server{mux: mux, loginController: loginController}
	return server, nil
}

func (s *Server) Start() error {
	s.mux.HandleFunc("POST /token/generate", s.loginController.CreateTokenPair)
	s.mux.HandleFunc("POST /token/refresh", s.loginController.RefreshAccess)

	handler := middleware.Logging(s.mux)
	handler = middleware.PanicRecovery(handler)
	log.Println("Server started")
	return http.ListenAndServe(":"+os.Getenv("SERVER_PORT"), handler)
}

func (s *Server) Stop() {
	if err := s.loginController.Close(); err != nil {
		panic(err)
	}
	log.Println("Server stopped")
}
