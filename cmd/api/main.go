package main

import (
	"GoJwt/internal/config"
	"GoJwt/internal/server"
)

func main() {
	config.NewConfig().Init()
	newServer, err := server.NewServer()
	if err != nil {
		panic(err)
	}
	defer newServer.Stop()

	if err := newServer.Start(); err != nil {
		panic(err)
	}

}
