package shadow

import "encoding/binary"

// Set statically for the major of the package
const (
	// Offset and sizes
	magic_bytes_offset = 0 // Where it all began 🥹
	magic_bytes_size   = 3

	VHL_offset = (magic_bytes_offset + magic_bytes_size)
	VHL_size   = 1

	client_id_offset = (VHL_offset + VHL_size)
	client_id_size   = 4

	txid_offset = (client_id_offset + client_id_size) // Transaction ID
	txid_size   = 4

	message_type_offset = (txid_offset + txid_size)
	message_type_size   = 1

	flags_offset = (message_type_offset + message_type_size)
	flags_size   = 1

	reserved_offset = (flags_offset + flags_size)
	reserved_size   = 1

	body_len_offset = (reserved_offset + reserved_size)
	body_len_size   = 1

	// First byte is version. Second byte is header length in number of 32 bit words
	// The header length is in case we ever need to add options later on down the line
	// so that we do not have to rewrite any filters to reflect changing offsets.
	header_len_words = uint8((body_len_offset + body_len_size) / 4) // Number of 32 bit words is 4 bytes each
)

// Keydra Message Type
// This should really be its own file
type KeydraMessageType uint8

const (
	KeydraHello KeydraMessageType = iota
	KeydraRegister
	KeydraDeregister
)

var messageName = map[KeydraMessageType]string{
	KeydraHello:      "Hello",
	KeydraRegister:   "Register",
	KeydraDeregister: "Deregister",
}

// Stringer for printing out
func (kmt KeydraMessageType) String() string {
	return messageName[kmt]
}

// Flags types
// This should really be its own file
type KeydraFlag uint8

const (
	KeydraFlagNew               KeydraFlag = 2 ^ iota // 1
	KeydraFlagEncrypt           KeydraFlag = 2 ^ iota // 2
	KeydraFlagTrace             KeydraFlag = 2 ^ iota // 4
	KeydraFlagStateless         KeydraFlag = 2 ^ iota // 8
	KeydraFlagRetry             KeydraFlag = 2 ^ iota // 16
	KeydraFlagRatchet           KeydraFlag = 2 ^ iota // 32
	KeydraFlagAuthorizePacket   KeydraFlag = 2 ^ iota // 64
	KeydraFlagAuthorizeRequired KeydraFlag = 2 ^ iota // 128
)

var flagString = map[KeydraFlag]string{
	KeydraFlagNew:               "New Transmission",
	KeydraFlagEncrypt:           "Encrypted Packet",
	KeydraFlagTrace:             "Trace Transaction",
	KeydraFlagStateless:         "Stateless Transaction",
	KeydraFlagRetry:             "Retry Packet",
	KeydraFlagRatchet:           "Ratchet DH Key",
	KeydraFlagAuthorizePacket:   "Authorization Provided",
	KeydraFlagAuthorizeRequired: "Authorization Required",
}

func (kf KeydraFlag) String() string {
	return flagString[kf]
}

// TLV struct
// Bit 6 is constructed, meaning the value contains other TLV's. Bit 7 is
// AAAAAA B C - A is the Tag, B is constructed, C is reserved
// Making things reserved is super convenient, because I basically dont have to know what its for, just that some day I might want it, and it makes me look better.
type TLV struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// Back to business.
// Packet interface
type KeydraPacket interface {
	setClientId(CiD []byte)
	setTransactionId(TxID []byte)
	setMessageType()
	setFlag()
	serialize() ([]byte, error)
	calculateBodyLen() uint8
}

// Datagram struct
type KeydraDatagramHeader struct {
	// Magic bytes
	MagicBytes uint32 // This is 24 bits, we will bitshift 8 to the left, then 8 to the right to garuntee value whenever header is assembled.

	// We have a transaction ID and client ID and not a reimplementation of seq and ack
	// because at some stage down the line we may wish to add seq and ack as options,
	// and have client ID and TxID serve as IP:PORT (CiD:TxID) and have the options
	// hold SEQ and ACK for each CiD:TxID combo.
	TransactionID uint32
	ClientID      uint32

	// Message type
	MessageType KeydraMessageType

	// Flags
	Flags KeydraFlag

	// reserved
	Reserved uint8 // Can be anything. Treated as 0 by my implementation.

	// Calculated Fields
	BodyLen uint8
}

type KeydraDatagram struct {
	// Implements
	KeydraPacket
	KeydraDatagramHeader
}

func (kd KeydraDatagram) setClientId(CiD []byte) {
	kd.KeydraDatagramHeader.ClientID = binary.BigEndian.Uint32(CiD)
}

func (kd KeydraDatagram) setTransactionId(TxID []byte) {
	kd.KeydraDatagramHeader.ClientID = binary.BigEndian.Uint32(TxID)
}

func (kd KeydraDatagram) setMessageType(messageType KeydraMessageType) {
	kd.KeydraDatagramHeader.MessageType = messageType
}

func (kd KeydraDatagram) setFlag(flag KeydraFlag) {
	kd.KeydraDatagramHeader.Flags = flag
}

func (kd KeydraDatagram) serialize(magicBytes []byte, version uint8) ([]byte, error) {
	// By shifting the magic bytes we open the final byte of the first word, then set the upper half to the version, and the lower half to the header length
	magicBytesAsInteger := binary.BigEndian.Uint32(magicBytes)
	identifierAndVHL := magicBytesAsInteger << 8                              // 11111111 11111111 11111111 11111111 -> 11111111 11111111 11111111 00000000
	identifierAndVHL = identifierAndVHL + uint32(version<<4+header_len_words) // 11111111 11111111 11111111 00000000 + 00000000 00000000 00000000 (VERSION: 4 bits)(Len: 4 bits)

	// Assemble CID and TXID

	// Return
	return nil, nil
}

func (kd KeydraDatagram) calculateBodyLen() uint8 {
	return 0
}
