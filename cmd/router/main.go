package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	authDatabase "github.com/M0hammedImran/go-server-template/internal/auth/database"
	"github.com/M0hammedImran/go-server-template/internal/ecogas"
	"github.com/M0hammedImran/go-server-template/internal/ecowatt"
	userDB "github.com/M0hammedImran/go-server-template/internal/users/database"

	docs "github.com/M0hammedImran/go-server-template/api"
	"github.com/M0hammedImran/go-server-template/internal/cache"
	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"github.com/M0hammedImran/go-server-template/internal/database"
	"github.com/M0hammedImran/go-server-template/internal/emailer"
	"github.com/M0hammedImran/go-server-template/internal/users"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	if os.Getenv("ENV") == "local" {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
		log.Println("Environment variables loaded")
	}

	// load configs and sets default logger configs.
	conf, err := config.Load(os.Getenv("CONFIG_PATH"))
	if err != nil {
		log.Fatal(err)
	}

	logging.SetConfig(&logging.Config{
		Encoding:    conf.LoggingConfig.Encoding,
		Level:       zapcore.Level(conf.LoggingConfig.Level),
		Development: conf.LoggingConfig.Development,
	})
	defer logging.DefaultLogger().Sync()

	// setup application(di + run server)
	app := fx.New(
		fx.Supply(conf),

		fx.Supply(logging.DefaultLogger().Desugar()),

		fx.WithLogger(func(log *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: log.Named("fx")}
		}),

		fx.StopTimeout(conf.ServerConfig.GracefulShutdown+time.Second),

		fx.Invoke(printAppInfo),

		fx.Provide(

			// setup database
			database.NewDatabase,

			// setup cache
			cache.NewCacher,

			// setup ecowatt packages
			ecowatt.NewEcoWatt,
			ecogas.NewEcoGas,

			// setup emailer packages
			emailer.NewHandler,

			// setup auth packages
			authDatabase.NewAuthTokenDB,

			// setup user packages
			userDB.NewUserDB,
			users.NewHandler,

			ecowatt.NewHandler,
			ecogas.NewHandler,
			// server
			newServer,
		),

		fx.Invoke(
			users.RouteV1,
			ecowatt.RouteV1,
			ecogas.RouteV1,

			func(r *gin.Engine) {},
		),
	)

	app.Run()
}

func newServer(lc fx.Lifecycle, cfg *config.Config) *gin.Engine {
	if cfg.ServerConfig.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()

	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Title = "Bywatt API"
	docs.SwaggerInfo.Description = "Internal API for Bywatt"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	corsConfig.AllowMethods = []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"}
	r.Use(cors.New(corsConfig))

	r.Use(secure.New(secure.Config{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline'; img-src * 'self' data: https:;",
		IENoOpen:              true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
	}))

	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.NoRoute(func(ctx *gin.Context) {
		ctx.JSON(http.StatusNotFound, gin.H{"message": "Not Found"})
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerConfig.Port),
		Handler:      r,
		ReadTimeout:  cfg.ServerConfig.ReadTimeout,
		WriteTimeout: cfg.ServerConfig.WriteTimeout,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logging.FromContext(ctx).Infof("Start to rest api server :%d", cfg.ServerConfig.Port)
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logging.DefaultLogger().Errorw("failed to close http server", "err", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			logging.FromContext(ctx).Info("Stopped rest api server")
			return srv.Shutdown(ctx)
		},
	})
	return r
}

func printAppInfo(cfg *config.Config) {
	b, _ := json.MarshalIndent(&cfg, "", "  ")
	logging.DefaultLogger().Infof("application information\n%s", string(b))
}
