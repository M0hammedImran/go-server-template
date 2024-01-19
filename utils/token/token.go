package token

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
)

type CreateTokenResponse struct {
	Token     string `json:"token"`
	Claims    jwt.RegisteredClaims
	ExpiresAt time.Time
}

func GenerateAccessToken(userUUID, tokenUUID string) (CreateTokenResponse, error) {
	oneDay := 24 * time.Hour
	claims := jwt.RegisteredClaims{
		Audience:  []string{"Bywatt-API"},
		Issuer:    "Bywatt",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(oneDay)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        tokenUUID,
		Subject:   userUUID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		logging.DefaultLogger().Errorf("Error signing access token %v", err)
		return CreateTokenResponse{}, err
	}

	return CreateTokenResponse{Token: tokenString, Claims: claims, ExpiresAt: time.Now().Add(oneDay)}, nil
}

func GenerateRefreshToken(userUUID, tokenUUID string) (CreateTokenResponse, error) {
	oneWeek := 7 * 24 * time.Hour
	claims := jwt.RegisteredClaims{
		ID:        tokenUUID,
		Subject:   userUUID,
		Audience:  []string{"Bywatt-API"},
		Issuer:    "Bywatt",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(oneWeek)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return CreateTokenResponse{}, err
	}

	return CreateTokenResponse{Token: tokenString, Claims: claims, ExpiresAt: time.Now().Add(oneWeek)}, nil
}

var ErrorInvalidToken error = errors.New("invalid token")

// ValidateAccessToken validates the access token extracted from the context using the provided `cache.Cacher`.
// It returns the parsed claims of the token if it is valid, otherwise it returns an error.
// The function also checks if the access token exists in the cache and matches the provided token string.
func ValidateAccessToken(c *gin.Context, cacher cache.Cacher) (*jwt.RegisteredClaims, error) {
	logger := logging.FromContext(c)
	tokenString := ExtractToken(c)
	if tokenString == "" {
		logger.Errorw("[ValidateAccessToken] Error extracting token from context")
		return nil, ErrorInvalidToken
	}

	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	var value string

	if err := cacher.Get(c, GetAccessTokenRedisKey(claims), &value); err != nil {
		logger.Errorw("[ValidateAccessToken] Error getting access token from redis", "err", err)
		return nil, ErrorInvalidToken
	}

	logger.Infow("ValidateAccessToken", "value", value, "tokenString", tokenString)
	if value != tokenString {
		logger.Errorw("[ValidateAccessToken] Error validating access token", "value", value, "tokenString", tokenString)
		return nil, ErrorInvalidToken
	}

	return claims, nil
}

func ParseToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		logging.DefaultLogger().Errorf("Error parsing token %v", err)
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)

	if !ok || !token.Valid || claims.ID == "" {
		logging.DefaultLogger().Errorf("Error validating token: %+v", token)
		logging.DefaultLogger().Errorf("Error validating ok %+v", ok)
		logging.DefaultLogger().Errorf("Error validating claims %+v", claims)
		return nil, ErrorInvalidToken
	}

	return claims, nil
}

func ExtractToken(c *gin.Context) string {
	bearerToken := c.Request.Header.Get("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}

	return ""
}

func ExtractTokenID(c *gin.Context) (string, error) {
	tokenString := ExtractToken(c)

	token, err := ParseToken(tokenString)
	if err != nil {
		return "", err
	}

	return token.ID, nil
}

func GetAccessTokenRedisKey(claims *jwt.RegisteredClaims) string {
	key := claims.Subject + ":" + claims.ID + ":access"
	return key
}

func GetRefreshTokenRedisKey(claims *jwt.RegisteredClaims) string {
	key := claims.Subject + ":" + claims.ID + ":refresh"
	return key
}

func ValidateRefreshToken(refreshToken string) error {
	_, err := ParseToken(refreshToken)
	if err != nil {
		logging.DefaultLogger().Errorf("Error parsing refresh token: %s", err.Error())
		return err
	}

	return nil
}

func PurgeOldTokensByRefreshToken(refreshToken string) error {
	_, err := ParseToken(refreshToken)
	if err != nil {
		return err
	}
	// _, err = redis.RedisClient.Del(context.Background(), GetRefreshTokenRedisKey(claims)).Result()
	// if err != nil {
	// 	logging.DefaultLogger().Errorf("Error purging old refresh token: %s", err.Error())
	// }
	// _, err = redis.RedisClient.Del(context.Background(), GetAccessTokenRedisKey(claims)).Result()
	// if err != nil {
	// 	logging.DefaultLogger().Errorf("Error purging old access token: %s", err.Error())
	// }

	return nil
}
