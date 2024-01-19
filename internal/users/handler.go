package users

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	authDatabase "github.com/M0hammedImran/go-server-template/internal/auth/database"
	authModel "github.com/M0hammedImran/go-server-template/internal/auth/model"
	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/database"
	"github.com/M0hammedImran/go-server-template/internal/emailer"
	"github.com/M0hammedImran/go-server-template/internal/middleware"
	"github.com/M0hammedImran/go-server-template/internal/middleware/handler"
	userDB "github.com/M0hammedImran/go-server-template/internal/users/database"
	"github.com/M0hammedImran/go-server-template/internal/users/model"
	"github.com/M0hammedImran/go-server-template/pkg/validate"
	"github.com/M0hammedImran/go-server-template/utils"
	"github.com/M0hammedImran/go-server-template/utils/token"
)

type Handler struct {
	userDB      userDB.UserDB
	authTokenDB authDatabase.AuthTokenDB
	redisCacher cache.Cacher
	emailer     emailer.Emailer
}

// currentUser handles GET /v1/api/user/me
func (h *Handler) currentUser(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		currentUser := middleware.MustCurrentUser(c)
		find, err := h.userDB.FindByEmail(c.Request.Context(), currentUser.Email)
		if err != nil {
			if database.IsRecordNotFoundErr(err) {
				return handler.NewErrorResponse(http.StatusNotFound, handler.NotFoundEntity, "not found current user", nil)
			}
			return &handler.Response{Err: err}
		}

		return handler.NewSuccessResponse(http.StatusOK, NewUserResponse(find))
	})
}

type AddUserInput struct {
	Email     string `json:"email" binding:"required"`
	Password  string `json:"password" binding:"required"`
	Role      string `json:"role" binding:"required"`
	FirstName string `json:"firstName" binding:"required"`
	LastName  string `json:"lastName"`
}

func (h *Handler) addUser(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)

		secret := c.DefaultQuery("secret", "NO_SECRET")

		if secret == "NO_SECRET" || secret != c.GetString("ADMIN_SECRET") {
			return handler.NewErrorResponse(http.StatusNotFound, handler.InvalidBodyValue, "Not Allowed", nil)
		}

		var input AddUserInput

		if err := c.ShouldBindJSON(&input); err != nil {
			logger.Errorw("account.handler.update failed to bind", "err", err)
			var details []*validate.ValidationErrDetail
			if vErrs, ok := err.(validator.ValidationErrors); ok {
				details = validate.ValidationErrorDetails(&input, "json", vErrs)
			}
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "invalid user request in body", details)
		}

		user := model.User{
			Role:      model.Role(input.Role),
			FirstName: input.FirstName,
			LastName:  input.LastName,
			Email:     input.Email,
			Password:  input.Password,
		}

		if err := h.userDB.Save(c.Request.Context(), &user); err != nil {
			if database.IsKeyConflictErr(err) {
				return handler.NewErrorResponse(http.StatusConflict, handler.DuplicateEntry, "duplicate email address", nil)
			}

			return handler.NewInternalErrorResponse(err)
		}

		return handler.NewSuccessResponse(http.StatusOK, NewUserResponse(&user))
	})
}

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

type Token struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
}

// @Summary 	Refresh Access and Refresh Tokens
// @Description Refresh Access and Refresh Tokens
// @Tags 		Auth
// @Produce 	json
// @Success 	200 {object} handler.SuccessResponse
// @Failure 	400 {object} handler.ErrorResponse
// @Failure 	500 {object} handler.ErrorResponse
// @Router 		/v1/refresh [post]
func (h *Handler) refreshAccessToken(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)
		refreshToken := token.ExtractToken(c)

		claims, err := token.ParseToken(refreshToken)
		if err != nil {
			logger.Errorf("Error parsing refresh token: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		if err = token.ValidateRefreshToken(refreshToken); err != nil {
			logger.Errorf("Error validating refresh token: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		user, err := h.userDB.FindByUUID(c, claims.Subject)
		if err != nil {
			logger.Errorf("Error getting user by uuid: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		authToken, err := h.authTokenDB.FindAuthTokenByUUID(c, claims.ID)
		if err != nil {
			logger.Errorf("Error getting auth token by uuid: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		newAccessToken, err := token.GenerateAccessToken(user.UUID.String(), claims.ID)
		if err != nil {
			logger.Errorf("Error generating access token: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		newRefreshToken, err := token.GenerateRefreshToken(user.UUID.String(), claims.ID)
		if err != nil {
			logger.Errorf("Error generating refresh token: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		at := authModel.AuthToken{
			AccessToken:  newAccessToken.Token,
			RefreshToken: newRefreshToken.Token,
		}

		if err = h.authTokenDB.Update(c, authToken.UUID.String(), &at); err != nil {
			logger.Errorf("Error updating auth token: %s", err.Error())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}
		_ = token.PurgeOldTokensByRefreshToken(refreshToken)

		accessTokenKey := token.GetAccessTokenRedisKey(&newAccessToken.Claims)
		if err := h.redisCacher.SetTTL(context.Background(), accessTokenKey, newAccessToken.Token, -1*time.Since(newAccessToken.ExpiresAt)); err != nil {
			logger.Errorf("Error setting access_token to redis %v", err)
			_ = h.authTokenDB.DeleteAuthToken(c, authToken.UUID.String())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		refreshTokenKey := token.GetRefreshTokenRedisKey(&newRefreshToken.Claims)
		if err := h.redisCacher.SetTTL(context.Background(), refreshTokenKey, newRefreshToken.Token, -1*time.Since(newRefreshToken.ExpiresAt)); err != nil {
			logger.Errorf("Error setting refresh_token to redis %v", err)
			_ = h.authTokenDB.DeleteAuthToken(c, authToken.UUID.String())
			return handler.NewErrorResponse(http.StatusBadRequest, handler.ErrorCode(ErrInvalidRefreshToken.Error()), "invalid refresh token", nil)
		}

		return handler.NewSuccessResponse(http.StatusOK, Token{
			AccessToken:  newAccessToken.Token,
			RefreshToken: newRefreshToken.Token,
			ExpiresAt:    strconv.FormatInt(newAccessToken.ExpiresAt.Unix(), 10),
		})
	})
}

var (
	LoginContactSupport    = ("Unable to log you in. Please contact support or try again later.")
	ErrLoginContactSupport = errors.New(LoginContactSupport)

	ForgotPasswordContactSupport    = ("Unable to send OTP. Please contact support or try again later.")
	ErrForgotPasswordContactSupport = errors.New(ForgotPasswordContactSupport)

	ResetPasswordContactSupport    = ("Unable to reset password. Please contact support or try again later.")
	ErrResetPasswordContactSupport = errors.New(ResetPasswordContactSupport)
)

type LoginInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// @Summary 	Login
// @Description Login
// @Tags 		Auth
// @Produce 	json
// @Param		Input 	body 	LoginInput	true	" "
// @Success 	200 {object} handler.SuccessResponse
// @Failure 	400 {object} handler.ErrorResponse
// @Failure 	500 {object} handler.ErrorResponse
// @Router 		/v1/login [post]
func (h *Handler) login(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)

		var input LoginInput

		if err := c.ShouldBindJSON(&input); err != nil {
			logger.Errorw("account.handler.update failed to bind", "err", err)
			var details []*validate.ValidationErrDetail
			if vErrs, ok := err.(validator.ValidationErrors); ok {
				details = validate.ValidationErrorDetails(&input, "json", vErrs)
			}
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "invalid user request in body", details)
		}

		user, err := h.userDB.FindByEmail(c, input.Email)
		if err != nil {
			if database.IsRecordNotFoundErr(err) {
				return handler.NewErrorResponse(http.StatusNotFound, handler.NotFoundEntity, "email/password does not match", nil)
			}

			return handler.NewInternalErrorResponse(err)
		}

		err = MatchesPassword(user.Password, input.Password)
		if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
			return handler.NewErrorResponse(http.StatusNotFound, handler.InvalidBodyValue, "email/password does not match", nil)
		}

		tokenUUID := uuid.New()

		accessToken, err := token.GenerateAccessToken(user.UUID.String(), tokenUUID.String())
		if err != nil {
			logger.Errorf("Error generating access token: %s", err.Error())
			return handler.NewInternalErrorResponse(ErrLoginContactSupport)
		}

		refreshToken, err := token.GenerateRefreshToken(user.UUID.String(), tokenUUID.String())
		if err != nil {
			logger.Errorf("Error generating refresh token: %s", err.Error())
			return handler.NewInternalErrorResponse(ErrLoginContactSupport)
		}
		logger.Debugw("login", "accessToken", accessToken, "refreshToken", refreshToken)
		authToken := authModel.AuthToken{AccessToken: accessToken.Token, RefreshToken: refreshToken.Token, UserID: user.ID, UUID: tokenUUID}
		err = h.authTokenDB.Save(c, &authToken)
		if err != nil {
			logger.Errorf("Error creating auth token: %s", err.Error())
			return handler.NewInternalErrorResponse(ErrLoginContactSupport)
		}

		accessTokenKey := token.GetAccessTokenRedisKey(&accessToken.Claims)
		if err := h.redisCacher.SetTTL(c, accessTokenKey, accessToken.Token, -1*time.Since(accessToken.ExpiresAt)); err != nil {
			logger.Errorf("Error setting access_token to redis %v", err)
			_ = h.authTokenDB.DeleteAuthToken(c, authToken.UUID.String())
			return handler.NewInternalErrorResponse(ErrLoginContactSupport)
		}

		refreshTokenKey := token.GetRefreshTokenRedisKey(&refreshToken.Claims)
		if err := h.redisCacher.SetTTL(c, refreshTokenKey, refreshToken.Token, -1*time.Since(refreshToken.ExpiresAt)); err != nil {
			logger.Errorf("Error setting refresh_token to redis %v", err)
			_ = h.authTokenDB.DeleteAuthToken(c, authToken.UUID.String())
			return handler.NewInternalErrorResponse(ErrLoginContactSupport)
		}

		return handler.NewSuccessResponse(http.StatusOK, Token{
			AccessToken:  accessToken.Token,
			RefreshToken: refreshToken.Token,
			ExpiresAt:    strconv.FormatInt(accessToken.ExpiresAt.Unix(), 10),
		})
	})
}

// update handles PUT /v1/api/user
func (h *Handler) update(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)
		currentUser := middleware.MustCurrentUser(c)
		type RequestBody struct {
			User struct {
				Username string `json:"username" binding:"omitempty"`
				Password string `json:"password" binding:"omitempty,min=5"`
				Bio      string `json:"bio"`
				Image    string `json:"image"`
			} `json:"user"`
		}
		var body RequestBody
		if err := c.ShouldBindJSON(&body); err != nil {
			logger.Errorw("account.handler.update failed to bind", "err", err)
			var details []*validate.ValidationErrDetail
			if vErrs, ok := err.(validator.ValidationErrors); ok {
				details = validate.ValidationErrorDetails(&body.User, "json", vErrs)
			}
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "invalid user request in body", details)
		}

		acc, err := h.userDB.FindByEmail(c.Request.Context(), currentUser.Email)
		if err != nil {
			if database.IsRecordNotFoundErr(err) {
				return handler.NewErrorResponse(http.StatusNotFound, handler.NotFoundEntity, "not found account", nil)
			}
			return handler.NewInternalErrorResponse(err)
		}

		if body.User.Password != "" {
			password, err := EncodePassword(body.User.Password)
			if err != nil {
				logger.Errorw("account.handler.update failed to encode password", "err", err)
				return &handler.Response{Err: err}
			}
			acc.Password = password
		}

		err = h.userDB.Update(c.Request.Context(), currentUser.Email, acc)
		if err != nil {
			if database.IsRecordNotFoundErr(err) {
				logger.Errorw("account.handler.update failed to update user because not found user", "err", err)
			}
			return handler.NewInternalErrorResponse(err)
		}
		return handler.NewSuccessResponse(http.StatusOK, NewUserResponse(acc))
	})
}

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}

// @Summary 	Forgot Password
// @Description Forgot Password
// @Tags 		Auth
// @Produce 	json
// @Param		Input 	body 	ForgotPasswordInput	true	" "
// @Success 	200 {object} handler.SuccessResponse
// @Failure 	400 {object} handler.ErrorResponse
// @Failure 	500 {object} handler.ErrorResponse
// @Router 		/v1/forgot-password [post]
func (h *Handler) forgotPassword(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)
		var input ForgotPasswordInput
		if err := c.ShouldBindJSON(&input); err != nil {
			logger.Errorw("account.handler.update failed to bind", "err", err)
			var details []*validate.ValidationErrDetail
			if vErrs, ok := err.(validator.ValidationErrors); ok {
				details = validate.ValidationErrorDetails(&input, "json", vErrs)
			}
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "invalid user request in body", details)
		}

		user, err := h.userDB.FindByEmail(c, input.Email)
		if err != nil {
			logger.Errorf("Error getting user by email: %v", err)
			return handler.NewSuccessResponse(http.StatusOK, "If your email address exists in our system, you will receive a OTP at your email address in a few minutes.")
		}

		otp, err := utils.CreateOtp(6)
		if err != nil {
			logger.Errorf("Error creating OTP: %v", err)
			return handler.NewInternalErrorResponse(ErrForgotPasswordContactSupport)
		}

		u := model.User{
			OTP:       otp,
			OTPExpiry: time.Now().Add(10 * time.Minute),
		}

		if err := h.userDB.Update(c, user.Email, &u); err != nil {
			logger.Errorf("Error updating user: %v", err)
			return handler.NewInternalErrorResponse(ErrForgotPasswordContactSupport)
		}

		email := emailer.Email{
			To:      []string{user.Email},
			Subject: "Bywatt - OTP for Forgot Password",
			Body:    fmt.Sprintf("OTP: %s", otp),
		}

		if err = h.emailer.SendEmail(email); err != nil {
			logger.Errorf("Error sending email: %v", err)
			return handler.NewInternalErrorResponse(ErrForgotPasswordContactSupport)
		}

		return handler.NewSuccessResponse(http.StatusOK, "success")
	})
}

type ResetPasswordInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	OTP      string `json:"otp" binding:"required"`
}

// @Summary 	Reset Password
// @Description Reset Password
// @Tags 		Auth
// @Produce 	json
// @Param		Input 	body 	ResetPasswordInput	true	" "
// @Success 	200 {object} handler.SuccessResponse
// @Failure 	400 {object} handler.ErrorResponse
// @Failure 	500 {object} handler.ErrorResponse
// @Router 		/v1/reset-password [post]
func (h *Handler) resetPassword(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c)

		var input ResetPasswordInput
		if err := c.ShouldBindJSON(&input); err != nil {
			logger.Errorw("account.handler.update failed to bind", "err", err)
			var details []*validate.ValidationErrDetail
			if vErrs, ok := err.(validator.ValidationErrors); ok {
				details = validate.ValidationErrorDetails(&input, "json", vErrs)
			}
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "invalid user request in body", details)
		}

		user, err := h.userDB.FindByEmail(c, input.Email)
		if err != nil {
			logger.Errorf("Error getting user by email: %v", err)
			return handler.NewErrorResponse(http.StatusBadRequest, handler.NotFoundEntity, "user not found", nil)
		}
		logger.Debugw("resetPassword", "user", user)
		if user.OTPExpiry.Compare(time.Now()) < 0 {
			logger.Errorw("OTP expired", "otp", user.OTPExpiry)
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "OTP expired", nil)
		}

		if user.OTP != input.OTP {
			logger.Errorf("OTP does not match")
			return handler.NewErrorResponse(http.StatusBadRequest, handler.InvalidBodyValue, "OTP does not match", nil)
		}

		password, err := EncodePassword(input.Password)
		if err != nil {
			logger.Errorw("handler.resetPassword failed to encode password", "err", err)
			return handler.NewInternalErrorResponse(ErrResetPasswordContactSupport)
		}

		u := model.User{
			Password:  password,
			OTPExpiry: time.Now().Add(-24 * time.Hour),
		}

		if err := h.userDB.Update(c, user.Email, &u); err != nil {
			logger.Errorf("Error updating user: %v", err)
			return handler.NewInternalErrorResponse(ErrResetPasswordContactSupport)
		}

		return handler.NewSuccessResponse(http.StatusOK, "success")
	})
}

// RouteV1 routes user api given config and gin.Engine
func RouteV1(cfg *config.Config, h *Handler, r *gin.Engine) {
	v1 := r.Group("v1")
	v1.Use(middleware.RequestIDMiddleware(), middleware.TimeoutMiddleware(cfg.ServerConfig.WriteTimeout))

	{
		v1.POST("login", h.login)

		v1.Use(func(ctx *gin.Context) {
			ctx.Set("ADMIN_SECRET", cfg.AdminConfig.Secret)
			ctx.Next()
		})
		v1.POST("add-user", h.addUser)
		v1.POST("refresh", h.refreshAccessToken)
		v1.POST("forgot-password", h.forgotPassword)
		v1.POST("reset-password", h.resetPassword)
	}

	v1.Use(middleware.AuthMiddleware(h.userDB, h.redisCacher))
	{
		v1.GET("users/me", h.currentUser)
	}
}

func NewHandler(userDB userDB.UserDB, authTokenDB authDatabase.AuthTokenDB, redisCacher cache.Cacher, emailer emailer.Emailer) *Handler {
	return &Handler{
		userDB:      userDB,
		authTokenDB: authTokenDB,
		redisCacher: redisCacher,
		emailer:     emailer,
	}
}
