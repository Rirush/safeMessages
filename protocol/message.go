package protocol

type Message struct {
	Type        string `json:",omitempty"`
	Signature   string `json:",omitempty"`
	Source      string `json:",omitempty"`
	Destination string `json:",omitempty"`
	Body        string `json:",omitempty"`
}

type ServerCertificate struct {
	ServerID    string
	Expiration  string
	SigningKey  []byte
	Description string
}
