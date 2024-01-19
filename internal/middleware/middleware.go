package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/users/database"
	"github.com/M0hammedImran/go-server-template/internal/users/model"
	"github.com/M0hammedImran/go-server-template/pkg/trace"
	"github.com/M0hammedImran/go-server-template/utils/token"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	XRequestIdKey = "X-Request-ID" // request id header key
)

// RequestIDMiddleware attach request id and logger to context
// 1. extract request id from header if exist, otherwise generate
// 2. attach request id to logger and store it to context
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestId := c.Request.Header.Get(XRequestIdKey)
		if requestId == "" {
			requestId = uuid.New().String()
		}

		c.Request = c.Request.WithContext(trace.WithRequestID(c, requestId))
		logger := logging.DefaultLogger().With("requestId", requestId)
		c.Request = c.Request.WithContext(logging.WithLogger(c, logger))
		c.Writer.Header().Set(XRequestIdKey, requestId)
	}
}

// TimeoutMiddleware attach deadline to gin.Request.Context
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)

		defer func() {
			if ctx.Err() == context.DeadlineExceeded {
				c.AbortWithStatus(http.StatusGatewayTimeout)
			}
			cancel()
		}()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// LoggingMiddleware use logging.DefaultLogger() i.e *zap.SugaredLogger with x-request-id
func LoggingMiddleware(skipPaths ...string) gin.HandlerFunc {
	skip := make(map[string]struct{}, len(skipPaths))
	for _, path := range skipPaths {
		skip[path] = struct{}{}
	}

	return func(c *gin.Context) {
		// skip logging
		if _, ok := skip[c.FullPath()]; ok {
			c.Next()
			return
		}

		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		// process request
		c.Next()

		logger := logging.FromContext(c.Request.Context())
		timestamp := time.Now()
		latency := timestamp.Sub(start)
		latencyValue := latency.String()
		clientIP := c.ClientIP()
		method := c.Request.Method
		status := c.Writer.Status()
		if rawQuery != "" {
			path = path + "?" + rawQuery
		}
		// append logger keys if not success or too slow latency.
		if status != http.StatusOK {
			logger = logger.With("status", status)
		}
		if latency > time.Second*3 {
			logger = logger.With("latency", latencyValue)
		}
		logger.Infof("[ARTICLE_API] %v | %3d | %s | %13v | %15s | %-7s %#v",
			timestamp.Format("2006/01/02 - 15:04:05"),
			status,
			latency,
			latencyValue,
			clientIP,
			method,
			path,
		)
	}
}

var identityKey = "id"

func CurrentUser(c *gin.Context) (*model.User, bool) {
	data, ok := c.Get(identityKey)
	if !ok {
		return nil, false
	}
	acc, ok := data.(*model.User)
	return acc, ok
}

func MustCurrentUser(c *gin.Context) *model.User {
	acc, ok := CurrentUser(c)
	if ok {
		return acc
	}
	panic("no account in gin.Context")
}

func unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm=bywatt")

	logging.FromContext(c).Infow("middleware.jwt.Unauthorized", "code", code, "message", message)
	c.JSON(code, gin.H{"code": code, "message": message})
	c.Abort()
}

func AuthMiddleware(userDB database.UserDB, cacher cache.Cacher) func(c *gin.Context) {
	return func(c *gin.Context) {
		logger := logging.FromContext(c)
		claims, err := token.ValidateAccessToken(c, cacher)
		if err != nil {
			logger.Errorw("middleware.jwt.AuthMiddleware", "err", err.Error())
			unauthorized(c, http.StatusUnauthorized, "unauthorized")
			return
		}

		logger.Debugw("middleware.jwt.AuthMiddleware", "claims", claims)
		c.Set("JWT_PAYLOAD", claims)
		user, err := userDB.FindByUUID(c, claims.Subject)
		if err != nil {
			logger.Errorw("middleware.jwt.AuthMiddleware", "err", err.Error())
			unauthorized(c, http.StatusUnauthorized, "unauthorized")
			return
		}

		logger.Debugw("middleware.jwt.AuthMiddleware", "user", user)
		c.Set(identityKey, user)
		c.Next()
	}
}

func IsAdmin(c *gin.Context) {
	logger := logging.FromContext(c)

	rawUser, exists := c.Get(identityKey)
	if !exists {
		logger.Errorw("middleware.jwt.IsAdmin", "err", "identityKey not found")
		unauthorized(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	logger.Debugw("middleware.jwt.IsAdmin", "rawUser", rawUser)
	user, ok := rawUser.(*model.User)
	if !ok {
		logger.Error("middleware.jwt.IsAdmin", "err", "unable to cast rawUser to *model.User")
		unauthorized(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	logger.Debugw("middleware.jwt.IsAdmin", "user", user)
	if !user.IsAdmin() {
		unauthorized(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	logger.Info("middleware.jwt.IsAdmin authenticated")
	c.Next()
}
