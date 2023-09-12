package service

import (
	"crypto/sha1"
	"fmt"
	"time"
	"todo-app"
	"todo-app/pkg/repository"

	"github.com/dgrijalva/jwt-go"
)

const (
	salt       = "sgsgdhrfwsfsdfhgn"
	signingKey = "qwesdfgSwF435sefwdf2"
	tokenTTL   = (12 * time.Hour)
)

type tokenClaims struct {
	jwt.StandardClaims
	UserId int `json:"user_id"`
}

type AuthSevice struct {
	repo repository.Authorization
}

func NewAuthService(repo repository.Authorization) *AuthSevice {
	return &AuthSevice{
		repo: repo,
	}
}

func (s *AuthSevice) CreateUser(user todo.User) (int, error) {
	user.Password = generatePasswordHash(user.Password)
	return s.repo.CreateUser(user)
}

func (s *AuthSevice) GenerateToken(username, password string) (string, error) {
	user, err := s.repo.GetUser(username, generatePasswordHash(password))

	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &tokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		user.Id,
	})
	fmt.Println(token.SignedString([]byte(signingKey)))

	return token.SignedString([]byte(signingKey))
}

func generatePasswordHash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))

	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}
