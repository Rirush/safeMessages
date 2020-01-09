package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/alexflint/go-arg"
	"os"
)

type InitSubcommandArguments struct {
	ConnectionString string `arg:"-c" help:"database connection string (needs to be specified if configuration file doesn't exist yet)"`
}

type Arguments struct {
	Init *InitSubcommandArguments `arg:"subcommand:init" help:"initialize server working directory"`
}

var arguments = Arguments{}

func init() {
	arg.MustParse(&arguments)
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
	config := Configuration{}
	config.Database.ConnectionString = arguments.Init.ConnectionString
	f, err := os.OpenFile("server.toml", os.O_WRONLY|os.O_CREATE, 0700)
	if err != nil {
		fmt.Println("Cannot create configuration file:", err)
		os.Exit(1)
	}
	encoder := toml.NewEncoder(f)
	err = encoder.Encode(config)
	if err != nil {
		fmt.Println("Cannot encode configuration to file:", err)
		os.Exit(1)
	}
}

func RunServer() {
	config := Configuration{}
	_, err := toml.DecodeFile("server.toml", &config)
	if err != nil {
		fmt.Println("Cannot decode server configuration:", err)
		os.Exit(1)
	}

}
