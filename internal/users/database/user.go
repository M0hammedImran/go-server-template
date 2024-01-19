package database

import (
	"context"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/database"
	"github.com/M0hammedImran/go-server-template/internal/users/model"
	"gorm.io/gorm"
)

//go:generate mockery --name UserDB --filename user_mock.go
type UserDB interface {
	// Save saves a given user
	Save(ctx context.Context, user *model.User) error

	// Update updates a given user
	Update(ctx context.Context, email string, user *model.User) error

	// FindByEmail returns an user with given email if exist
	FindByEmail(ctx context.Context, email string) (*model.User, error)

	// FindByUUID returns an user with given uuid if exist
	FindByUUID(ctx context.Context, uuid string) (*model.User, error)
}

// NewUserDB creates a new user db with given db
func NewUserDB(db *gorm.DB, cacher cache.Cacher) UserDB {
	if cacher == nil {
		return &userDB{db: db}
	}

	return newUserCacheDB(cacher, &userDB{db: db})
}

type userDB struct {
	db *gorm.DB
}

func (a *userDB) Save(ctx context.Context, user *model.User) error {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("user.db.Save", "user", user)

	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		logger.Error("user.db.Save failed to save", "err", err)
		if database.IsKeyConflictErr(err) {
			return database.ErrKeyConflict
		}
		return err
	}
	return nil
}

func (a *userDB) Update(ctx context.Context, email string, user *model.User) error {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("user.db.Update", "user", user)

	fields := make(map[string]interface{})
	if user.Email != "" {
		fields["username"] = user.Email
	}
	if user.Password != "" {
		fields["password"] = user.Password
	}
	if user.OTP != "" {
		fields["otp"] = user.OTP
	}
	if user.FirstName != "" {
		fields["first_name"] = user.FirstName
	}
	if user.LastName != "" {
		fields["last_name"] = user.LastName
	}

	if !user.OTPExpiry.IsZero() {
		fields["otp_expiry"] = user.OTPExpiry
	}

	chain := db.WithContext(ctx).
		Model(&model.User{}).
		Where("email = ?", email).
		UpdateColumns(fields)

	if chain.Error != nil {
		logger.Error("user.db.Update failed to update", "err", chain.Error)
		return chain.Error
	}

	if chain.RowsAffected == 0 {
		return database.ErrNotFound
	}

	return nil
}

func (a *userDB) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("user.db.FindByEmail", "email", email)

	var acc model.User
	if err := db.WithContext(ctx).Where("email = ?", email).First(&acc).Error; err != nil {
		logger.Error("user.db.FindByEmail failed to find", "err", err)
		if database.IsRecordNotFoundErr(err) {
			return nil, database.ErrNotFound
		}

		return nil, err
	}

	return &acc, nil
}

func (a *userDB) FindByUUID(ctx context.Context, uuid string) (*model.User, error) {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("user.db.FindByUUID", "uuid", uuid)

	var acc model.User
	if err := db.WithContext(ctx).Where("uuid = ?", uuid).First(&acc).Error; err != nil {
		logger.Error("user.db.FindByUUID failed to find", "err", err)
		if database.IsRecordNotFoundErr(err) {
			return nil, database.ErrNotFound
		}

		return nil, err
	}

	return &acc, nil
}
