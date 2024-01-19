package model

import (
	userModel "github.com/M0hammedImran/go-server-template/internal/users/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthToken struct {
	gorm.Model

	UserID       uint
	User         userModel.User
	AccessToken  string
	RefreshToken string
	UUID         uuid.UUID `gorm:"uniqueIndex"`
}
