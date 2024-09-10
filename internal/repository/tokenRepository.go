package repository

import (
	"GoJwt/package/jwt"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"os"
)

type TokenRepository interface {
	Close() error
	AddToken(jti, token string, exp *jwt.Time) error
	RemoveToken(jti string) error
	CheckToken(jti, refresh string) (bool, error)
}

type PostgresTokenRepository struct {
	db *sql.DB
}

func NewTokenRepository() (*PostgresTokenRepository, error) {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	conStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	con, err := sql.Open("postgres", conStr)

	if err != nil {
		return nil, err
	}
	return &PostgresTokenRepository{db: con}, con.Ping()
}

func (rep *PostgresTokenRepository) Close() error {
	err := rep.db.Close()
	if err != nil {
		return err
	}
	return nil
}

func (rep *PostgresTokenRepository) AddToken(jti, token string, exp *jwt.Time) error {
	tx, err := rep.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	h := hmac.New(sha256.New, []byte(os.Getenv("SALT"))) //not bcrypt, cuz token too large for bcrypt
	if _, err = h.Write([]byte(token)); err != nil {
		return err
	}
	encrypted := h.Sum(nil)
	_, err = tx.Exec("INSERT INTO refresh_token (jti, token, exp) VALUES ($1, $2, $3)", jti,
		base64.RawURLEncoding.EncodeToString(encrypted), exp.Time)
	if err != nil {
		return err
	}

	_ = tx.Commit()
	return nil
}

func (rep *PostgresTokenRepository) RemoveToken(jti string) error {
	tx, err := rep.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM refresh_token WHERE jti = $1", jti)
	if err != nil {
		return err
	}
	_ = tx.Commit()

	return nil
}

func (rep *PostgresTokenRepository) CheckToken(jti, refresh string) (bool, error) {
	row := rep.db.QueryRow("SELECT token FROM refresh_token WHERE jti = $1 AND exp > now()", jti)
	if err := row.Err(); err != nil {
		return false, err
	}
	token := ""
	err := row.Scan(&token)
	if err != nil {
		return false, errors.New(fmt.Sprintf("no such valid token with jti %s", jti))
	}
	h := hmac.New(sha256.New, []byte(os.Getenv("SALT")))
	if _, err = h.Write([]byte(refresh)); err != nil {
		return false, err
	}
	encoded := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(encoded) == token, nil
}

func (rep *PostgresTokenRepository) RemoveInvalidTokens() error {
	_, err := rep.db.Exec("DELETE FROM refresh_token WHERE exp <= now()")
	return err
}
