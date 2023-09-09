package service

import (
	"crypto/sha1"
	"fmt"
	"todo-app"
	"todo-app/pkg/repository"
)

const salt = "sgsgdhrfwsfsdfhgn"

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

func generatePasswordHash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))

	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}
