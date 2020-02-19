package main

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/rocketlaunchr/dbq"
	"time"
)

var db *sqlx.DB

type Entity struct {
	Address uuid.UUID `db:"address"`
	Type    string    `db:"type"`
}

func AllocateUUID(typ string) Entity {
	allocatedUUID := uuid.New()
	ent := Entity{
		Address: allocatedUUID,
		Type:    typ,
	}
	_, err := db.Exec("INSERT INTO entities (address, type) VALUES ($1, $2)", ent.Address, ent.Type)
	if err != nil {
		panic("Cannot insert entity into database: " + err.Error())
	}
	return ent
}

type Device struct {
	Address            uuid.UUID `db:"address"`
	Name               string    `db:"name"`
	Description        string    `db:"description"`
	PublicSignatureKey []byte    `db:"public_signature_key"`
	PublicExchangeKey  []byte    `db:"public_exchange_key"`
	DiscoverKey        []byte    `db:"discover_key"`
	IsActive           bool      `db:"is_active"`
	IsDiscoverable     bool      `db:"is_discoverable"`
}

func (dev *Device) Insert() {
	_, err := db.Exec("INSERT INTO devices (address, name, description, public_signature_key, public_exchange_key) VALUES ($1, $2, $3, $4, $5)",
		dev.Address, dev.Name, dev.Description, dev.PublicSignatureKey, dev.PublicExchangeKey)
	if err != nil {
		panic("Cannot insert device into database: " + err.Error())
	}
	return
}

func FindDevice(address uuid.UUID) (dev Device, err error) {
	ent := Entity{}
	err = db.Get(&ent, "SELECT * FROM entities WHERE address = $1", address)
	if err != nil {
		return Device{}, errors.New("no such device found")
	}
	if ent.Type != "device" {
		return Device{}, errors.New("no such device found")
	}
	err = db.Get(&dev, "SELECT * FROM devices WHERE address = $1", address)
	return
}

func (dev *Device) SetActive() {
	dbq.MustE(context.Background(), db, "UPDATE devices WHERE address = $1 SET is_active = true", nil, dev.Address)
}

func (dev *Device) SetInactive() {
	dbq.MustE(context.Background(), db, "UPDATE devices WHERE address = $1 SET is_active = false", nil, dev.Address)
}

func CreateDevice(ent Entity) Device {
	device := Device{
		Address:        ent.Address,
		IsActive:       false,
		IsDiscoverable: false,
	}
	return device
}

type Identity struct {
	Address             uuid.UUID `db:"address"`
	Username            string    `db:"username"`
	Name                string    `db:"name"`
	Description         string    `db:"description"`
	PublicSignatureKey  []byte    `db:"public_signature_key"`
	PrivateSignatureKey []byte    `db:"private_signature_key"`
	PublicExchangeKey   []byte    `db:"public_exchange_key"`
	PrivateExchangeKey  []byte    `db:"private_exchange_key"`
	VerificationHash    []byte    `db:"verification_hash"`
	DiscoverKey         []byte    `db:"discover_key"`
	IsDiscoverable      bool      `db:"is_discoverable"`
}

type Conversation struct {
	Address     uuid.UUID `db:"address"`
	Creator     uuid.UUID `db:"creator"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	IsPrivate   bool      `db:"is_private"`
	IsDirect    bool      `db:"is_direct"`
	IsEncrypted bool      `db:"is_encrypted"`
	IsStorable  bool      `db:"is_storable"`
}

type PendingConversationMember struct {
	RequestID    uint64    `db:"request_id"`
	Conversation uuid.UUID `db:"conversation"`
	Member       uuid.UUID `db:"member"`
	PendingKey   []byte    `db:"pending_key"`
	AddedAt      time.Time `db:"added_at"`
}

type KeyChange struct {
	ChangeID              uint64    `db:"change_id"`
	Identity              uuid.UUID `db:"identity"`
	ChangedAt             time.Time `db:"changed_at"`
	OldPublicSignatureKey []byte    `db:"old_public_signature_key"`
	OldPublicExchangeKey  []byte    `db:"old_public_exchange_key"`
}

type LinkedDevice struct {
	LinkID   uint64    `db:"link_id"`
	Identity uuid.UUID `db:"identity"`
	Device   uuid.UUID `db:"device"`
	LinkedAt time.Time `db:"linked_at"`
}

type ConversationKey struct {
	KeyID        uint64    `db:"key_id"`
	Identity     uuid.UUID `db:"identity"`
	Conversation uuid.UUID `db:"conversation"`
	EncryptedKey []byte    `db:"encrypted_key"`
}

type ConversationToken struct {
	TokenID      uint64    `db:"token_id"`
	AccessToken  []byte    `db:"access_token"`
	Issuer       uuid.UUID `db:"issuer"`
	Conversation uuid.UUID `db:"conversation"`
	IssuedAt     time.Time `db:"issued_at"`
	IsActive     bool      `db:"is_active"`
}

type ConversationMember struct {
	LinkID       uint64    `db:"link_id"`
	Conversation uuid.UUID `db:"conversation"`
	Member       uuid.UUID `db:"member"`
	UsedToken    uint64    `db:"used_token"`
}

type Message struct {
	GlobalMessageID uint64    `db:"global_message_id"`
	MessageID       uint64    `db:"message_id"`
	Sender          uuid.UUID `db:"sender"`
	Recipient       uuid.UUID `db:"recipient"`
	Signature       []byte    `db:"signature"`
	SentAt          time.Time `db:"sent_at"`
	IsEncrypted     bool      `db:"is_encrypted"`
	Contents        []byte    `db:"contents"`
}
