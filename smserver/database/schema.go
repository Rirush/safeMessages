package database

import (
	"database/sql"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"time"
)

var db *sqlx.DB

func Store(_db *sqlx.DB) {
	db = _db
}

const (
	insertDeviceSql = "INSERT INTO devices VALUES ($1, $2, $3, $4)"
	queryDeviceByIDSql = "SELECT * FROM devices WHERE address = $1"
	updateDeviceSql = "UPDATE devices SET key = $2, name = $3, description = $4 WHERE address = $1"
	insertIdentitySql = "INSERT INTO identities VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
	queryIdentityByAddressSql = "SELECT * FROM identities WHERE address = $1"
	queryIdentityByUsernameSql = "SELECT * FROM identities WHERE username ILIKE $1"
	updateIdentitySql = "UPDATE identities SET name = $2, bio = $3 WHERE address = $1"
	linkDeviceSql = "INSERT INTO identity_link VALUES (DEFAULT, $1, $2)"
	unlinkDeviceSql = "DELETE FROM identity_link WHERE identity = $1 AND device = $2"
	listLinkedDevicesSql = "SELECT device FROM identity_link WHERE identity = $1"
	listLinkedIdentitiesSql = "SELECT identity FROM identity_link WHERE device = $1"
	insertChatSql = "INSERT INTO chats VALUES ($1, $2, $3, $4)"
	updateChatSql = "UPDATE chats SET title = $2, description = $3, discovery_key = $4 WHERE address = $1"
	getChatsSql = "SELECT chat FROM chat_members WHERE member = $1"
	insertMessageSql = "INSERT INTO messages VALUES (DEFAULT, $1, $2, $3, $4, $5, NOW())"

	bulkQueryDevicesSql = "SELECT * FROM devices WHERE address IN (?)"
	bulkQueryChatsSql   = "SELECT * FROM chats WHERE address IN (?)"
	bulkQueryIdentitiesSql = "SELECT * FROM identities WHERE address IN (?)"
)

var (
	insertDeviceStmt *sqlx.Stmt
	queryDeviceByIDStmt *sqlx.Stmt
	updateDeviceStmt *sqlx.Stmt
	insertIdentityStmt *sqlx.Stmt
	queryIdentityByAddressStmt *sqlx.Stmt
	queryIdentityByUsernameStmt *sqlx.Stmt
	updateIdentityStmt *sqlx.Stmt
	linkDeviceStmt *sqlx.Stmt
	unlinkDeviceStmt *sqlx.Stmt
	listLinkedDevicesStmt *sqlx.Stmt
	listLinkedIdentitiesStmt *sqlx.Stmt
	insertChatStmt *sqlx.Stmt
	updateChatStmt *sqlx.Stmt
	getChatsStmt *sqlx.Stmt
	insertMessageStmt *sqlx.Stmt
)

func PrepareStatements() error {
	var err error
	insertDeviceStmt, err = db.Preparex(insertDeviceSql)
	if err != nil {
		return err
	}
	queryDeviceByIDStmt, err = db.Preparex(queryDeviceByIDSql)
	if err != nil {
		return err
	}
	updateDeviceStmt, err = db.Preparex(updateDeviceSql)
	if err != nil {
		return err
	}
	insertIdentityStmt, err = db.Preparex(insertIdentitySql)
	if err != nil {
		return err
	}
	queryIdentityByAddressStmt, err = db.Preparex(queryIdentityByAddressSql)
	if err != nil {
		return err
	}
	queryIdentityByUsernameStmt, err = db.Preparex(queryIdentityByUsernameSql)
	if err != nil {
		return err
	}
	updateIdentityStmt, err = db.Preparex(updateIdentitySql)
	if err != nil {
		return err
	}
	linkDeviceStmt, err = db.Preparex(linkDeviceSql)
	if err != nil {
		return err
	}
	unlinkDeviceStmt, err = db.Preparex(unlinkDeviceSql)
	if err != nil {
		return err
	}
	listLinkedDevicesStmt, err = db.Preparex(listLinkedDevicesSql)
	if err != nil {
		return err
	}
	listLinkedIdentitiesStmt, err = db.Preparex(listLinkedIdentitiesSql)
	if err != nil {
		return err
	}
	insertChatStmt, err = db.Preparex(insertChatSql)
	if err != nil {
		return err
	}
	updateChatStmt, err = db.Preparex(updateChatSql)
	if err != nil {
		return err
	}
	getChatsStmt, err = db.Preparex(getChatsSql)
	if err != nil {
		return err
	}
	insertMessageStmt, err = db.Preparex(insertMessageSql)
	return err
}

type Device struct {
	Address uuid.UUID
	Key []byte
	Name string
	Description string
}

func (d *Device) Insert() error {
	d.Address = uuid.New()
	_, err := insertDeviceStmt.Exec(d.Address, d.Key, d.Name, d.Description)
	return err
}

func (d *Device) FindByAddress(address uuid.UUID) error {
	result := queryDeviceByIDStmt.QueryRowx(address)
	err := result.StructScan(d)
	return err
}

func (d *Device) Update() error {
	_, err := updateDeviceStmt.Exec(d.Address, d.Key, d.Name, d.Description)
	return err
}

type Identity struct {
	Address uuid.UUID
	Username string
	Name string
	Bio string
	SignatureKey []byte `db:"signature_key"`
	EncryptedSignatureKey []byte `db:"encrypted_signature_key"`
	ExchangeKey []byte `db:"exchange_key"`
	EncryptedExchangeKey []byte `db:"encrypted_exchange_key"`
	VerificationHash []byte `db:"verification_hash"`
}

func (i *Identity) Insert() error {
	i.Address = uuid.New()
	_, err := insertIdentityStmt.Exec(i.Address, i.Username, i.Name, i.Bio, i.SignatureKey, i.EncryptedSignatureKey, i.ExchangeKey, i.EncryptedExchangeKey, i.VerificationHash)
	return err
}

func (i *Identity) FindByAddress(address uuid.UUID) error {
	result := queryIdentityByAddressStmt.QueryRowx(address)
	err := result.StructScan(i)
	return err
}

func (i *Identity) FindByUsername(username string) error {
	result := queryIdentityByUsernameStmt.QueryRowx(username)
	err := result.StructScan(i)
	return err
}

func (i *Identity) Update() error {
	_, err := updateIdentityStmt.Exec(i.Address, i.Name, i.Bio)
	return err
}

type IdentityLink struct {
	LinkID uint64 `db:"link_id"`
	Identity uuid.UUID
	Device uuid.UUID
}

func (i *Identity) Link(d *Device) error {
	_, err := linkDeviceStmt.Exec(i.Address, d.Address)
	return err
}

func (i *Identity) Unlink(d *Device) error {
	_, err := unlinkDeviceStmt.Exec(i.Address, d.Address)
	return err
}

func (i *Identity) ListLinkedDevices() ([]*Device, error) {
	result, err := listLinkedDevicesStmt.Queryx(i.Address)
	if err != nil {
		return nil, err
	}
	var addresses []uuid.UUID
	for result.Next() {
		var address uuid.UUID
		err = result.Scan(&address)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	query, args, err := sqlx.In(bulkQueryDevicesSql, addresses)
	if err != nil {
		return nil, err
	}
	query = db.Rebind(query)
	result, err = db.Queryx(query, args...)
	if err != nil {
		return nil, err
	}
	var devices []*Device
	for result.Next() {
		device := &Device{}
		err = result.StructScan(device)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (d *Device) ListLinkedIdentities() ([]*Identity, error) {
	result, err := listLinkedDevicesStmt.Queryx(d.Address)
	if err != nil {
		return nil, err
	}
	var addresses []uuid.UUID
	for result.Next() {
		var address uuid.UUID
		err = result.Scan(&address)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return []*Identity{}, nil
	}
	query, args, err := sqlx.In(bulkQueryIdentitiesSql, addresses)
	if err != nil {
		return nil, err
	}
	query = db.Rebind(query)
	result, err = db.Queryx(query, args...)
	if err != nil {
		return nil, err
	}
	var identities []*Identity
	for result.Next() {
		identity := &Identity{}
		err = result.StructScan(identity)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

type Chat struct {
	Address uuid.UUID
	Title string
	Description string
	DiscoveryKey sql.NullString `db:"discovery_key"`
}

func (c *Chat) Insert() error {
	c.Address = uuid.New()
	_, err := insertChatStmt.Exec(c.Address, c.Title, c.Description, c.DiscoveryKey)
	return err
}

//func (c *Chat) FindPrivateChat(memberA, memberB *Identity) error {
//}

//func (c *Chat) InviteMembers(members []*Identity) error {
//}

//func (c *Chat) FindByKey(key string) error {
//}

func (c *Chat) Update() error {
	_, err := updateChatStmt.Exec(c.Address, c.Title, c.Description, c.DiscoveryKey)
	return err
}

func (i *Identity) GetJoinedChats() ([]*Chat, error) {
	result, err := getChatsStmt.Queryx(i.Address)
	if err != nil {
		return nil, err
	}
	var addresses []uuid.UUID
	for result.Next() {
		var address uuid.UUID
		err = result.Scan(&address)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	query, args, err := sqlx.In(bulkQueryChatsSql, addresses)
	if err != nil {
		return nil, err
	}
	query = db.Rebind(query)
	result, err = db.Queryx(query, args...)
	if err != nil {
		return nil, err
	}
	var chats []*Chat
	for result.Next() {
		chat := &Chat{}
		err = result.StructScan(chat)
		if err != nil {
			return nil, err
		}
		chats = append(chats, chat)
	}
	return chats, nil
}

type ChatMember struct {
	LinkID uint64 `db:"link_id"`
	Member uuid.UUID
	Chat uuid.UUID
}

type PendingMember struct {
	PendingID uint64 `db:"pending_id"`
	Member uuid.UUID
	InvitedBy uuid.UUID `db:"invited_by"`
	Chat string
}

type Message struct {
	GlobalMessageID uint64 `db:"global_message_id"`
	LocalMessageID uint64 `db:"local_message_id"`
	Sender uuid.UUID
	Signature []byte
	Message []byte
	Chat uuid.UUID
	SentAt time.Time
}

func (m *Message) Insert() error {
	_, err := insertMessageStmt.Exec(m.LocalMessageID, m.Sender, m.Signature, m.Message, m.Chat)
	return err
}

//func (c *Chat) GetMessagesInChat(limit, offset uint64) ([]*Message, error) {
//}

//func GetMessagesSince(receiver Identity, date time.Time) ([]*Message, error) {
//}