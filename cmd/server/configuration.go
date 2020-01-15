package main

type Configuration struct {
	Database struct {
		ConnectionString string
	}
	Encryption struct {
		Certificate string
		Key         string
	}
	Connection struct {
		BindAddress string
	}
	Debug bool
}
