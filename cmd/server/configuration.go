package main

type Configuration struct {
	Database struct {
		ConnectionString string
	}
	Encryption struct {
		Certificate string
		Key         string
	}
	Debug bool
}
