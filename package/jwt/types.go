package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type Time struct {
	Time time.Time
}

func (t *Time) UnmarshalJSON(data []byte) error {
	parseInt, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	t.Time = time.Unix(parseInt, 0)
	return nil
}

func (t *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Time.Unix())
}

type Header struct {
	Algorithm string `json:"alg"`
	Typ       string `json:"typ"`
}

func NewHeader() *Header {
	return &Header{Algorithm: "HS256", Typ: "JWT"}
}

type Payload map[string]interface{}

func (p Payload) ParseAsString(key string) (string, error) {
	var (
		raw interface{}
		ok  bool
		val string
	)
	raw, ok = (p)[key]
	if !ok {
		return "", errors.New("key not found")
	}

	val, ok = raw.(string)
	if !ok {
		return "", errors.New(fmt.Sprintf("value of key %s isn't string", key))
	}
	return val, nil
}

func (p Payload) ParseAsTime(key string) (*Time, error) {
	var (
		raw interface{}
		ok  bool
		val Time
	)
	raw, ok = (p)[key]
	if !ok {
		return nil, errors.New(fmt.Sprintf("value not found by key: %s", key))
	}

	val, ok = raw.(Time)
	if !ok {
		return nil, errors.New(fmt.Sprintf("value of key %s isn't time", key))
	}
	return &val, nil
}
