package database

import (
	"time"

	authModel "github.com/M0hammedImran/go-server-template/internal/auth/model"
	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	usersModel "github.com/M0hammedImran/go-server-template/internal/users/model"
	"go.uber.org/zap/zapcore"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// NewDatabase creates a new database with given config
func NewDatabase(cfg *config.Config) (*gorm.DB, error) {
	var (
		db     *gorm.DB
		err    error
		logger = NewLogger(time.Second, true, zapcore.Level(cfg.DBConfig.LogLevel))
	)

	for i := 0; i <= 30; i++ {
		db, err = gorm.Open(postgres.Open(cfg.DBConfig.GetDSN()), &gorm.Config{Logger: logger})
		if err == nil {
			break
		}
		logging.DefaultLogger().Warnf("failed to open database: %v", err)
		time.Sleep(500 * time.Millisecond)
	}

	if err != nil {
		return nil, err
	}

	rawDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	rawDB.SetMaxOpenConns(cfg.DBConfig.Pool.MaxOpen)
	rawDB.SetMaxIdleConns(cfg.DBConfig.Pool.MaxIdle)
	rawDB.SetConnMaxLifetime(cfg.DBConfig.Pool.MaxLifetime)

	if cfg.DBConfig.Migrate.Enable {
		if err := db.AutoMigrate(authModel.AuthToken{}, usersModel.User{}); err != nil {
			return nil, err
		}
	}

	return db, nil
}
