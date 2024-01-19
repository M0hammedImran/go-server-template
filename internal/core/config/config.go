package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jeremywohl/flatten"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/s3"
)

type Config struct {
	ServerConfig  ServerConfig  `json:"server"`
	LoggingConfig LoggingConfig `json:"logging" yaml:"logging"`
	JwtConfig     JWTConfig     `json:"jwt"`
	DBConfig      DBConfig      `json:"db"`
	CacheConfig   CacheConfig   `json:"cache"`
	SMTPConfig    SMTPConfig    `json:"smtp"`
	EcoWattConfig EcoWattConfig `json:"ecowatt"`
	EcoGasConfig  EcoGasConfig  `json:"ecogas"`
	AdminConfig   struct {
		Secret string `json:"secret"`
	} `json:"admin"`
}

type EcoGasConfig struct {
	Host   string `json:"host"`
	ApiKey string `json:"apiKey"`
}

type EcoWattConfig struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Host         string `json:"host"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ServerConfig struct {
	Port             int           `json:"port"`
	ReadTimeout      time.Duration `json:"readTimeout"`
	WriteTimeout     time.Duration `json:"writeTimeout"`
	GracefulShutdown time.Duration `json:"gracefulShutdown"`
	Mode             string        `json:"mode"`
}

type LoggingConfig struct {
	Level       int    `json:"level"`
	Encoding    string `json:"encoding"`
	Development bool   `json:"development"`
}

type JWTConfig struct {
	Secret      string        `json:"secret"`
	SessionTime time.Duration `json:"sessionTime"`
}

type DBConfig struct {
	LogLevel int `json:"logLevel"`
	Migrate  struct {
		Enable bool   `json:"enable"`
		Dir    string `json:"dir"`
	} `json:"migrate"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Dbname   string `json:"dbname"`
	Port     int    `json:"port"`
	Pool     struct {
		MaxOpen     int           `json:"maxOpen"`
		MaxIdle     int           `json:"maxIdle"`
		MaxLifetime time.Duration `json:"maxLifetime"`
	} `json:"pool"`
}

func (c *DBConfig) GetDSN() string {
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d", c.Host, c.User, c.Password, c.Dbname, c.Port)
}

type CacheConfig struct {
	Enabled     bool          `json:"enabled"`
	Prefix      string        `json:"prefix"`
	Type        string        `json:"type"`
	TTL         time.Duration `json:"ttl"`
	RedisConfig RedisConfig   `json:"redis"`
}

type RedisConfig struct {
	DB           int           `json:"db"`
	Cluster      bool          `json:"cluster"`
	Endpoints    []string      `json:"endpoints"`
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	ReadTimeout  time.Duration `json:"readTimeout"`
	WriteTimeout time.Duration `json:"writeTimeout"`
	DialTimeout  time.Duration `json:"dialTimeout"`
	PoolSize     int           `json:"poolSize"`
	PoolTimeout  time.Duration `json:"poolTimeout"`
	MaxConnAge   time.Duration `json:"maxConnAge"`
	IdleTimeout  time.Duration `json:"idleTimeout"`
}

func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// load from default config
	err := k.Load(confmap.Provider(defaultConfig, "."), nil)
	if err != nil {
		log.Printf("[ERROR] failed to load default config. err: %v", err)
		return nil, err
	}

	// load from env
	err = k.Load(env.Provider("BYWATT_SERVER_", ".", func(s string) string {
		keys := strings.ToLower(strings.TrimPrefix(s, "BYWATT_SERVER_"))

		return strings.Replace(keys, "_", ".", -1)
	}), nil)

	if err != nil {
		log.Printf("[ERROR] failed to load config from env. err: %v", err)
	}

	// load from config file if exist
	if configPath != "" {
		path, err := filepath.Abs(configPath)
		if err != nil {
			log.Printf("[ERROR] failed to get absolute config path. configPath:%s, err: %v", configPath, err)
			return nil, err
		}
		log.Printf("load config file from %s", path)
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			log.Printf("[ERROR] failed to load config from file. err: %v", err)
			return nil, err
		}
	} else {
		// Load JSON config from s3.
		if err := k.Load(s3.Provider(s3.Config{
			AccessKey: os.Getenv("AWS_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("AWS_S3_SECRET_KEY"),
			Region:    os.Getenv("AWS_S3_REGION"),
			Bucket:    os.Getenv("AWS_S3_BUCKET"),
			ObjectKey: os.Getenv("AWS_S3_CONFIG_OBJECT_KEY"),
		}), yaml.Parser()); err != nil {
			log.Printf("[ERROR] failed to load config from s3. err: %v", err)
		}
	}

	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{Tag: "json", FlatPaths: false}); err != nil {
		log.Printf("[ERROR] failed to unmarshal with conf. err: %v", err)
		return nil, err
	}
	return &cfg, err
}

func (c *Config) MarshalJSON() ([]byte, error) {
	type conf Config
	alias := conf(*c)

	data, err := json.Marshal(&alias)
	if err != nil {
		return nil, err
	}

	flat, err := flatten.FlattenString(string(data), "", flatten.DotStyle)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	err = json.Unmarshal([]byte(flat), &m)
	if err != nil {
		return nil, err
	}

	maskKeys := map[string]struct{}{
		// add keys if u want to mask some properties.
		"jwt.secret":           {},
		"db.password":          {},
		"admin.secret":         {},
		"smtp.password":        {},
		"cache.redis.password": {},
	}

	for key, val := range m {
		if v, ok := val.(string); ok {
			m[key] = maskPassword(v)
		}
		if _, ok := maskKeys[key]; ok {
			switch v := val.(type) {
			case string:
				if v != "" {
					m[key] = "****"
				}
			default:
				m[key] = "****"
			}
		}
	}
	return json.Marshal(&m)
}

func maskPassword(val string) string {
	if val == "" {
		return ""
	}
	regex := regexp.MustCompile(`^(?P<protocol>.+?//)?(?P<username>.+?):(?P<password>.+?)@(?P<address>.+)$`)
	if !regex.MatchString(val) {
		return val
	}
	matches := regex.FindStringSubmatch(val)
	for i, v := range regex.SubexpNames() {
		if v == "password" {
			val = strings.ReplaceAll(val, matches[i], "****")
		}
	}
	return val
}

var defaultConfig = map[string]interface{}{
	"server.port":             8080,
	"server.readTimeout":      "5s",
	"server.mode":             "development",
	"server.writeTimeout":     "10s",
	"server.gracefulShutdown": "30s",

	"logging.level":       -1,
	"logging.encoding":    "console",
	"logging.development": true,

	"jwt.secret":      "secret-key",
	"jwt.sessionTime": "864000s",

	"db.logLevel":         1,
	"db.migrate.enable":   false,
	"db.migrate.dir":      "",
	"db.pool.maxOpen":     10,
	"db.pool.maxIdle":     5,
	"db.pool.maxLifetime": "5m",

	"db.host":     "localhost",
	"db.user":     "postgres",
	"db.password": "postgres",
	"db.dbname":   "service",
	"db.port":     5432,

	"cache.enabled":            false,
	"cache.db":                 1,
	"cache.prefix":             "article-",
	"cache.type":               "redis",
	"cache.ttl":                60 * time.Second,
	"cache.redis.cluster":      false,
	"cache.redis.endpoints":    []string{"localhost:6379"},
	"cache.redis.readTimeout":  "3s",
	"cache.redis.writeTimeout": "3s",
	"cache.redis.dialTimeout":  "5s",
	"cache.redis.poolSize":     10,
	"cache.redis.poolTimeout":  "1m",
	"cache.redis.maxConnAge":   "0",
	"cache.redis.idleTimeout":  "5m",
	"cache.redis.username":     "",
	"cache.redis.password":     "",

	"admin.secret":  "abc",
	"smtp.host":     "smtp.gmail.com",
	"smtp.port":     465,
	"smtp.username": "",
	"smtp.password": "",

	"ecowatt.clientId":     "",
	"ecowatt.clientSecret": "",
	"ecowatt.host":         "digital.iservices.rte-france.com",

	"ecogas.host":   "digital.iservices.rte-france.com",
	"ecogas.apiKey": "",
}
