package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

type Token struct {
	Header   *Header
	Payload  *Payload
	RawToken string
	Valid    bool
}

func NewToken(payload *Payload) (*Token, error) {
	token := &Token{
		Header:  NewHeader(),
		Payload: payload,
	}
	err := token.encodeToken()
	if err != nil {
		return nil, err
	}
	token.Valid = true
	return token, nil
}

func NewTokenFromRaw(rawToken string) (*Token, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("token has wrong number of parts")
	}
	headerHash, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	h := Header{}
	if err := json.Unmarshal(headerHash, &h); err != nil {
		return nil, err
	}

	payloadHash, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("invalid payload %s", parts[1])
		return nil, err
	}

	p := Payload{}
	if err = json.Unmarshal(payloadHash, &p); err != nil {
		return nil, err
	}

	token := &Token{Header: &h, Payload: &p, RawToken: rawToken}

	if err := token.Validate(); err != nil {
		return token, err
	}
	return token, nil
}

func (t *Token) encodeHeader() (*[]byte, error) {
	header, err := json.Marshal(t.Header)
	if err != nil {
		return nil, err
	}
	headerHash := make([]byte, base64.StdEncoding.EncodedLen(len(header)))
	base64.RawURLEncoding.Encode(headerHash, header)
	return &headerHash, nil
}

func (t *Token) encodePayload() (*[]byte, error) {
	payload, err := json.Marshal(t.Payload)
	if err != nil {
		return nil, err
	}
	payloadHash := make([]byte, base64.RawURLEncoding.EncodedLen(len(payload)))
	base64.RawURLEncoding.Encode(payloadHash, payload)
	return &payloadHash, err
}

func (t *Token) encodeToken() error {
	headerHash, err := t.encodeHeader()
	if err != nil {
		return err
	}
	payloadHash, err := t.encodePayload()
	if err != nil {
		return err
	}
	h := hmac.New(sha256.New, []byte(os.Getenv("JWT_SECRET")))
	h.Write(*headerHash)
	h.Write([]byte("."))
	h.Write(*payloadHash)
	signatureByte := h.Sum(nil)

	t.RawToken = fmt.Sprintf("%s.%s.%s", *headerHash, *payloadHash, base64.RawURLEncoding.EncodeToString(signatureByte))
	return nil
}

func (t *Token) Validate() error {
	t.Valid = false
	lastDot := strings.LastIndex(t.RawToken, ".")
	token := t.RawToken[:lastDot]
	h := hmac.New(sha256.New, []byte(os.Getenv("JWT_SECRET")))
	h.Write([]byte(token))
	signature := h.Sum(nil)
	givenSignature, err := base64.RawURLEncoding.DecodeString(t.RawToken[lastDot+1:])
	if err != nil {
		t.Valid = false
		return err
	}
	t.Valid = hmac.Equal(givenSignature, signature)
	return nil

}
