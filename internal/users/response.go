package users

import (
	"github.com/M0hammedImran/go-server-template/internal/users/model"
)

type UserResponse struct {
	User User `json:"user"`
}

type User struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

func NewUserResponse(acc *model.User) *UserResponse {
	return &UserResponse{
		User: User{
			Email:     acc.Email,
			FirstName: acc.FirstName,
			LastName:  acc.LastName,
		},
	}
}
