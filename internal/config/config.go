package config

import (
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env        string     `yaml:"env" env-default:"local" env-required:"true"`
	JWTSecret  string     `yaml:"jwt_secret" env-required:"true"`
	Database   Database   `yaml:"database"`
	HTTPServer HTTPServer `yaml:"http_server"`
}

type Database struct {
	Host                  string        `yaml:"host" env-default:"localhost" env-required:"true"`
	Port                  int           `yaml:"port" env-default:"5432" env-required:"true"`
	User                  string        `yaml:"user" env-default:"postgres" env-required:"true"`
	Password              string        `yaml:"password" env-default:"password" env-required:"true"`
	DBName                string        `yaml:"dbname" env-default:"app_db" env-required:"true"`
	MaxOpenConnections    int           `yaml:"max_open_connections" env-default:"50"`
	MaxIdleConnections    int           `yaml:"max_idle_connections" env-default:"10"`
	ConnectionMaxLifetime time.Duration `yaml:"connection_max_lifetime" env-default:"30m"`
}

type HTTPServer struct {
	Address           string        `yaml:"address" env-default:"localhost:8080" env-required:"true"`
	Timeout           time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout       time.Duration `yaml:"idle_timeout" env-default:"60s"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env-default:"2s"`
	WriteTimeout      time.Duration `yaml:"write_timeout" env-default:"8s"`
}

// Загружает файл конфигурации по пути из переменной окружения CONFIG_PATH
func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")

	if configPath == "" {
		log.Fatal("CONFIG_PATH is not set.")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("config file is not exists: %s", configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("can not read config file: %s", err)
	}
	return &cfg
}
