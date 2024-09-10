package config

import (
	"github.com/joho/godotenv"
	"log"
)

type Config struct {
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) Init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
	log.Println("Init environment")
}
