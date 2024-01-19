package database

import (
	"context"
	"fmt"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/users/model"
)

var _ UserDB = (*userCachedDB)(nil)

const (
	cacheKeyUserByEmail = "user-by-email"
	cacheKeyUserByUUID  = "user-by-uuid"
)

type userCachedDB struct {
	cacher   cache.Cacher
	delegate UserDB
}

func newUserCacheDB(cacher cache.Cacher, delegate UserDB) UserDB {
	return &userCachedDB{
		cacher:   cacher,
		delegate: delegate,
	}
}

func (ac *userCachedDB) Save(ctx context.Context, user *model.User) error {
	if err := ac.delegate.Save(ctx, user); err != nil {
		return err
	}
	key := ac.userByEmailCacheKey(user.Email)
	ac.cacher.Set(ctx, key, user)
	return nil
}

func (ac *userCachedDB) Update(ctx context.Context, email string, account *model.User) error {
	if err := ac.delegate.Update(ctx, email, account); err != nil {
		return err
	}
	key := ac.userByEmailCacheKey(email)
	if exists, _ := ac.cacher.Exists(ctx, key); exists {
		find, err := ac.delegate.FindByEmail(ctx, email)
		if err == nil {
			ac.cacher.Set(ctx, key, find)
		}
	}
	return nil
}

func (ac *userCachedDB) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	if cache.IsCacheSkip(ctx) {
		return ac.delegate.FindByEmail(ctx, email)
	}

	var (
		item model.User
		key  = ac.userByEmailCacheKey(email)
	)

	err := ac.cacher.Fetch(ctx, key, &item, func() (interface{}, error) {
		account, err := ac.delegate.FindByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		account.Password = ""
		return account, nil
	})

	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (ac *userCachedDB) FindByUUID(ctx context.Context, uuid string) (*model.User, error) {
	if cache.IsCacheSkip(ctx) {
		return ac.delegate.FindByUUID(ctx, uuid)
	}

	var (
		item model.User
		key  = ac.userByUUIDCacheKey(uuid)
	)

	err := ac.cacher.Fetch(ctx, key, &item, func() (interface{}, error) {
		account, err := ac.delegate.FindByUUID(ctx, uuid)
		if err != nil {
			return nil, err
		}
		account.Password = ""
		return account, nil
	})

	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (ac *userCachedDB) userByEmailCacheKey(email string) string {
	return fmt.Sprintf("%s.%s", cacheKeyUserByEmail, email)
}

func (ac *userCachedDB) userByUUIDCacheKey(email string) string {
	return fmt.Sprintf("%s.%s", cacheKeyUserByUUID, email)
}
