package ecowatt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/ecowatt/model"
	"github.com/M0hammedImran/go-server-template/internal/middleware"
	"github.com/M0hammedImran/go-server-template/internal/middleware/handler"
	userDB "github.com/M0hammedImran/go-server-template/internal/users/database"
	"github.com/gin-gonic/gin"
)

type EcoWatt interface {
	GetSignals(c context.Context) (*model.EcoWattResponse, error)
}

var ecowattCacheKey = "ecowatt"

type ecowatt struct {
	host     string
	clientID string
	secret   string

	AccessToken string
	ExpireTime  time.Time
}

func NewEcoWatt(c *config.Config) EcoWatt {
	logger := logging.FromContext(context.Background()).With("method", "ecowatt.NewEcoWatt")
	ew := &ecowatt{
		host:     c.EcoWattConfig.Host,
		clientID: c.EcoWattConfig.ClientID,
		secret:   c.EcoWattConfig.ClientSecret,
	}
	token, err := ew.getToken(context.Background())
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	ew.AccessToken = token.AccessToken
	ew.ExpireTime = time.Now().Add(time.Duration(token.ExpiresIn-10) * time.Second)

	return ew
}

type getTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (e *ecowatt) getToken(c context.Context) (*getTokenResponse, error) {
	logger := logging.FromContext(c).With("method", "ecowatt.handler.getToken")
	ecowattUrl := url.URL{
		Scheme: "https",
		Host:   e.host,
		Path:   "/token/oauth",
	}

	method := "GET"
	body := []byte(``)
	logger.Info(ecowattUrl.String())
	request, err := http.NewRequest(method, ecowattUrl.String(), bytes.NewReader(body))
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	request.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(e.clientID+":"+e.secret)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	defer response.Body.Close()
	byteString, _ := io.ReadAll(response.Body)
	var token getTokenResponse
	logger.Debugw("token response", "response", string(byteString))
	if err := json.Unmarshal(byteString, &token); err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return &token, nil
}

func (e *ecowatt) GetSignals(c context.Context) (*model.EcoWattResponse, error) {
	logger := logging.FromContext(c).With("method", "ecowatt.handler.GetSignal")
	var result model.EcoWattResponse

	if e.ExpireTime.Before(time.Now()) {
		logger.Info("ecowatt token expired")
		token, err := e.getToken(c)
		if err != nil {
			logger.Errorw("error getting token", "err", err)
			return nil, err
		}

		e.AccessToken = token.AccessToken
		e.ExpireTime = time.Now().Add(time.Duration(token.ExpiresIn-10) * time.Second)
	}

	ecowattUrl := url.URL{
		Scheme: "https",
		Host:   e.host,
		Path:   "/open_api/ecowatt/v5/signals",
	}
	method := "GET"
	body := []byte(``)
	request, err := http.NewRequest(method, ecowattUrl.String(), bytes.NewReader(body))
	if err != nil {
		logger.Errorw("error in constructing request", "err", err)
		return nil, err
	}
	request.Header.Add("Authorization", "Bearer "+e.AccessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Errorw("error in signals API", "err", err)
		return nil, err
	}

	defer response.Body.Close()
	byteString, _ := io.ReadAll(response.Body)
	if err := json.Unmarshal(byteString, &result); err != nil {
		logger.Errorw("error unmarshaling response", "err", err)

		return nil, err
	}

	return &result, nil
}

type Handler struct {
	ecowatt EcoWatt
	userDB  userDB.UserDB
	cache   cache.Cacher
}

// @Summary Get signals
// @Description Get signals
// @Tags EcoWatt
// @Produces json
// @Security BearerAuth
// @Success 200 {array} model.Signals
// @Router /v1/ecowatt/signals [get]
func (h *Handler) getSignals(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c).With("method", "ecowatt.handler.getSignals")
		var result model.EcoWattResponse

		if err := h.cache.Get(c, ecowattCacheKey, &result); err != nil {
			logger.Errorw("ecowatt cache miss", "err", err)
		}

		if len(result.Signals) > 0 {
			logger.Info("ecowatt cache hit")
			return handler.NewSuccessResponse(http.StatusOK, result.Signals)
		}

		signals, err := h.ecowatt.GetSignals(c)
		if err != nil {
			logger.Errorw("error getting signals", "err", err)
			return handler.NewInternalErrorResponse(err)
		}

		if err := h.cache.SetTTL(c, ecowattCacheKey, &signals, 1*time.Hour); err != nil {
			logger.Error("Error setting cache")
		}

		return handler.NewSuccessResponse(http.StatusOK, signals.Signals)
	})
}

func NewHandler(userDB userDB.UserDB, ecowatt EcoWatt, redisCacher cache.Cacher) *Handler {
	return &Handler{
		ecowatt: ecowatt,
		userDB:  userDB,
		cache:   redisCacher,
	}
}

func RouteV1(r *gin.Engine, cfg *config.Config, h *Handler) {
	v1 := r.Group("v1/ecowatt")
	v1.Use(middleware.RequestIDMiddleware(), middleware.TimeoutMiddleware(cfg.ServerConfig.WriteTimeout))

	v1.Use(middleware.AuthMiddleware(h.userDB, h.cache))
	v1.Use(middleware.IsAdmin)

	v1.GET("/signals", h.getSignals)
}
