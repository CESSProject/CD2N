package auth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JwtHelper struct {
	JwtKey []byte
	// by second
	ValidDuration int64
}

type UserInfo struct {
	Account []byte `json:"account,omitempty"`
}

func (u UserInfo) Marshal() []byte {
	jbytes, _ := json.Marshal(u)
	return jbytes
}

func (u *UserInfo) Unmarshal(data []byte) error {
	return json.Unmarshal(data, u)
}

type CustomClaims struct {
	User UserInfo `json:"user"`
	jwt.RegisteredClaims
}

var (
	jwtHelper *JwtHelper
)
var (
	ErrTokenExpired     error = errors.New("token is expired")
	ErrTokenNotValidYet error = errors.New("token not active yet")
	ErrTokenMalformed   error = errors.New("that's not even a token")
	ErrTokenInvalid     error = errors.New("couldn't handle this token")
)

func SetupAuth(jwtKey string, tokenValidDuration int64) {
	if jwtHelper != nil {
		return
	}
	jwtHelper = &JwtHelper{
		[]byte(jwtKey),
		tokenValidDuration,
	}
}

func Jwth() *JwtHelper {
	return jwtHelper
}

func (j *JwtHelper) GenerateToken(user UserInfo) (string, error) {
	claims := CustomClaims{
		user,
		jwt.RegisteredClaims{
			NotBefore: &jwt.NumericDate{Time: time.Now().Add(-30)},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Duration(j.ValidDuration))},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.JwtKey)
}

func (j *JwtHelper) GenerateTokenByClaims(claims CustomClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.JwtKey)
}

func (j *JwtHelper) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.JwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrTokenInvalid
}

func (j *JwtHelper) RefreshToken(tokenString string) (string, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.JwtKey, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		jwt.TimeFunc = time.Now
		claims.ExpiresAt = &jwt.NumericDate{Time: time.Now().Add(1 * time.Hour)}
		return j.GenerateTokenByClaims(*claims)
	}
	return "", ErrTokenInvalid
}
