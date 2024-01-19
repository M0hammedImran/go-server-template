package database

import (
	"context"

	"github.com/M0hammedImran/go-server-template/internal/auth/model"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/database"
	"gorm.io/gorm"
)

//go:generate mockery --name AuthTokenDB --filename auth_mock.go
type AuthTokenDB interface {
	// Save saves a given auth token
	Save(ctx context.Context, authToken *model.AuthToken) error

	// Update updates a given auth token
	Update(ctx context.Context, uuid string, authToken *model.AuthToken) error

	// DeleteAuthToken deletes an auth token with given uuid
	DeleteAuthToken(ctx context.Context, uuid string) error

	FindAuthTokenByUUID(ctx context.Context, uuid string) (*model.AuthToken, error)
}

type authTokenDB struct {
	db *gorm.DB
}

// NewAuthTokenDB creates a new auth token database
func NewAuthTokenDB(db *gorm.DB) AuthTokenDB {
	return &authTokenDB{db: db}
}

func (a *authTokenDB) Save(ctx context.Context, authToken *model.AuthToken) error {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("auth_token.db.Save", "authToken", authToken)

	if err := db.WithContext(ctx).Create(authToken).Error; err != nil {
		logger.Error("auth_token.db.Save failed to save", "err", err)
		if database.IsKeyConflictErr(err) {
			return database.ErrKeyConflict
		}

		return err
	}

	return nil
}

func (a *authTokenDB) DeleteAuthToken(ctx context.Context, uuid string) error {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("auth_token.db.DeleteAuthToken", "uuid", uuid)

	if err := db.WithContext(ctx).Where("uuid = ?", uuid).Delete(&model.AuthToken{}).Error; err != nil {
		logger.Error("auth_token.db.DeleteAuthToken failed to find", "err", err)

		if database.IsRecordNotFoundErr(err) {
			return database.ErrNotFound
		}

		return err
	}

	return nil
}

func (a *authTokenDB) Update(ctx context.Context, uuid string, authToken *model.AuthToken) error {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("authToken.db.Update", "authToken", authToken)

	fields := make(map[string]interface{})
	if authToken.AccessToken != "" {
		fields["access_token"] = authToken.AccessToken
	}
	if authToken.RefreshToken != "" {
		fields["refresh_token"] = authToken.RefreshToken
	}

	chain := db.WithContext(ctx).
		Model(&model.AuthToken{}).
		Where("uuid = ?", uuid).
		UpdateColumns(fields)

	if chain.Error != nil {
		logger.Error("authToken.db.Update failed to update", "err", chain.Error)
		return chain.Error
	}

	if chain.RowsAffected == 0 {
		return database.ErrNotFound
	}

	return nil
}

func (a *authTokenDB) FindAuthTokenByUUID(ctx context.Context, uuid string) (*model.AuthToken, error) {
	logger := logging.FromContext(ctx)
	db := database.FromContext(ctx, a.db)
	logger.Debugw("authToken.db.FindAuthTokenByUUID", "uuid", uuid)

	var authToken model.AuthToken
	if err := db.WithContext(ctx).Where("uuid = ?", uuid).First(&authToken).Error; err != nil {
		logger.Error("authToken.db.FindAuthTokenByUUID failed to find", "err", err)
		if database.IsRecordNotFoundErr(err) {
			return nil, database.ErrNotFound
		}

		return nil, err
	}

	return &authToken, nil
}
