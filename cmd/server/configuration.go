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
	Sentry struct {
		DSN string
	}
	Debug bool
}
