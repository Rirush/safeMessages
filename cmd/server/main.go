package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/alexflint/go-arg"
	"github.com/apsdehal/go-logger"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"os"
)

type InitSubcommandArguments struct {
	ConnectionString string `arg:"-c" help:"database connection string (needs to be specified if configuration file doesn't exist yet)"`
}

type Arguments struct {
	Init *InitSubcommandArguments `arg:"subcommand:init" help:"initialize server working directory"`
}

var arguments = Arguments{}

var defaultLogLevel = logger.WarningLevel

func init() {
	arg.MustParse(&arguments)
	logger.SetDefaultFormat("%{time} %{level} %{module}: %{message}")
}

func main() {
	switch {
	case arguments.Init != nil:
		InitSubcommand()
	default:
		RunServer()
	}
}

func InitSubcommand() {
	log, _ := logger.New("init", 1)
	config := Configuration{}
	config.Database.ConnectionString = arguments.Init.ConnectionString
	f, err := os.OpenFile("server.toml", os.O_WRONLY|os.O_CREATE, 0700)
	if err != nil {
		log.Fatalf("Cannot create configuration file: %v", err)
	}
	encoder := toml.NewEncoder(f)
	err = encoder.Encode(config)
	if err != nil {
		log.Fatalf("Cannot encode")
		fmt.Println("Cannot encode configuration to file:", err)
		os.Exit(1)
	}
	log.Info("Done")
}

func RunServer() {
	log, _ := logger.New("server", 1)
	log.Info("Starting server...")
	config := Configuration{}
	_, err := toml.DecodeFile("server.toml", &config)
	if err != nil {
		log.Fatalf("Cannot decode server configuration: %v", err)
	}
	log.Info("Configuration read successfully")

	if config.Debug {
		defaultLogLevel = logger.DebugLevel
	}
	log.SetLogLevel(defaultLogLevel)

	db, err = sqlx.Open("postgres", config.Database.ConnectionString)
	if err != nil {
		log.Fatalf("Cannot connect to the database: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(config.Encryption.Certificate, config.Encryption.Key)
	if err != nil {
		log.Fatalf("Cannot load X509 key pair: %v", err)
	}

	log.Infof("Starting TLS server at %s", config.Connection.BindAddress)
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, Rand: rand.Reader}
	listener, err := tls.Listen("tcp", config.Connection.BindAddress, &tlsConfig)
	if err != nil {
		log.Fatalf("Cannot start TLS server: %v", err)
		os.Exit(1)
	}

	Listen(listener)
}
