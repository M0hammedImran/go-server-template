package model

import (
	"html"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Role string

const (
	AdminRole Role = "admin"
	UserRole  Role = "user"
)

type User struct {
	gorm.Model

	FirstName string    `gorm:"size:50" json:"firstName"`
	LastName  string    `gorm:"size:50" json:"lastName"`
	Email     string    `gorm:"size:255;not null;uniqueIndex" json:"email"`
	Password  string    `gorm:"size:255;not null;" json:"password"`
	Role      Role      `gorm:"size:255;not null;default:'user'" json:"role"`
	UUID      uuid.UUID `gorm:"uniqueIndex"`

	OTP       string
	OTPExpiry time.Time
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.UUID = uuid.New()

	//turn password into hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hashedPassword)
	u.Email = html.EscapeString(strings.TrimSpace(u.Email))

	return nil
}

func (u *User) IsAdmin() bool {
	return u.Role == AdminRole
}

// Field is an enum providing valid fields for filtering.
type Field string

const (
	// FieldFirstName represents the first name field.
	FieldFirstName Field = "first_name"
	// FieldLastName represents the last name field.
	FieldLastName Field = "last_name"
	// FieldEmail represents the email field.
	FieldEmail Field = "email"
)

// MatchType is an enum providing valid matching mechanisms for filtering values.
type MatchType string

const (
	// MatchTypeLike represents a LIKE match.
	MatchTypeLike MatchType = "ILIKE"
	// MatchTypeEqual represents an exact match.
	MatchTypeEqual MatchType = "="
)

// Filter is a struct representing a filter for finding users.
type Filter struct {
	MatchType MatchType `json:"match_type"`
	Field     Field     `json:"field"`
	Value     string    `json:"value"`
}
