package ecogas

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/ecogas/model"
	"github.com/M0hammedImran/go-server-template/internal/middleware"
	"github.com/M0hammedImran/go-server-template/internal/middleware/handler"
	userDB "github.com/M0hammedImran/go-server-template/internal/users/database"
	"github.com/gin-gonic/gin"
)

type EcoGas interface {
	GetSignals(c context.Context) (*model.EcoGasSignalResponse, error)
}

var ecoGasCacheKey = "ecoGas"

type ecoGas struct {
	host   string
	ApiKey string
}

func NewEcoGas(c *config.Config) EcoGas {
	ew := &ecoGas{
		host:   c.EcoGasConfig.Host,
		ApiKey: c.EcoGasConfig.ApiKey,
	}

	return ew
}

func (e *ecoGas) GetSignals(c context.Context) (*model.EcoGasSignalResponse, error) {
	logger := logging.FromContext(c).With("method", "ecoGas.handler.GetSignal")
	var result model.EcoGasSignalResponse

	ecoGasUrl := url.URL{
		Scheme: "https",
		Host:   e.host,
		Path:   "/api/explore/v2.1/catalog/datasets/signal-ecogaz/records",
	}

	q := ecoGasUrl.Query()
	q.Set("apikey", e.ApiKey)
	q.Set("include_app_metas", "false")
	q.Set("include_links", "false")
	q.Set("lang", "en")
	q.Set("limit", "100")
	q.Set("offset", "0")
	q.Set("order_by", "gas_day desc")
	q.Set("select", "gas_day as date, color, indice_de_couleur as index")
	q.Set("timezone", "UTC")
	ecoGasUrl.RawQuery = q.Encode()

	logger.Infow("ecoGasUrl", "url", ecoGasUrl.String())
	method := "GET"
	body := []byte(``)
	request, err := http.NewRequest(method, ecoGasUrl.String(), bytes.NewReader(body))
	if err != nil {
		logger.Errorw("error in constructing request", "err", err)
		return nil, err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Errorw("error in signals API", "err", err)
		return nil, err
	}

	defer response.Body.Close()
	byteString, _ := io.ReadAll(response.Body)
	logger.Debugw("ecoGas response", "response", string(byteString))
	if err := json.Unmarshal(byteString, &result); err != nil {
		logger.Errorw("error unmarshaling response", "err", err)

		return nil, err
	}

	return &result, nil
}

type Handler struct {
	ecoGas EcoGas
	userDB userDB.UserDB
	cache  cache.Cacher
}

// @Summary Get signals
// @Description Get signals
// @Tags EcoGas
// @Produces json
// @Security BearerAuth
// @Success 200 {array} model.EcoGasSignalResponse
// @Router /v1/ecogas/signals [get]
func (h *Handler) getSignals(c *gin.Context) {
	handler.HandleRequest(c, func(c *gin.Context) *handler.Response {
		logger := logging.FromContext(c).With("method", "ecoGas.handler.getSignals")
		var result model.EcoGasSignalResponse

		if err := h.cache.Get(c, ecoGasCacheKey, &result); err != nil {
			logger.Errorw("ecoGas cache miss", "err", err)
		}

		if len(result.Results) > 0 {
			logger.Info("ecoGas cache hit")
			return handler.NewSuccessResponse(http.StatusOK, result)
		}

		signals, err := h.ecoGas.GetSignals(c)
		if err != nil {
			logger.Errorw("error getting signals", "err", err)
			return handler.NewInternalErrorResponse(err)
		}

		if err := h.cache.SetTTL(c, ecoGasCacheKey, &signals, 1*time.Hour); err != nil {
			logger.Error("Error setting cache")
		}

		return handler.NewSuccessResponse(http.StatusOK, signals)
	})
}

func NewHandler(userDB userDB.UserDB, ecoGas EcoGas, redisCacher cache.Cacher) *Handler {
	return &Handler{
		ecoGas: ecoGas,
		userDB: userDB,
		cache:  redisCacher,
	}
}

func RouteV1(r *gin.Engine, cfg *config.Config, h *Handler) {
	v1 := r.Group("v1/ecogas")
	v1.Use(middleware.RequestIDMiddleware(), middleware.TimeoutMiddleware(cfg.ServerConfig.WriteTimeout))
	v1.Use(middleware.AuthMiddleware(h.userDB, h.cache))
	v1.Use(middleware.IsAdmin)

	v1.GET("/signals", h.getSignals)
}
