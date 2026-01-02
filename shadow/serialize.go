package shadow

// Set statically for the major of the package
const (
	// Manually set magic bytes
	magic_bytes = 0x4B4340 // KCP
	version     = 1

	// Offset and sizes
	magic_bytes_offset = 0 // Where it all began 🥹
	magic_bytes_size   = 2

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
	//
	// VHL is version, header length
	header_len_words = (body_len_offset + body_len_size) / 4 // The same as multiplying by 8 then dividing by 32
	// (convert bytes to bits, then bits to 32 bit words)
	VHL = version*16 + header_len_words // Convert version to top 4 bits, keep header len as bottom 4 bits
)

// Keydra Message Type
// This should really be its own file
type KeydraMessageType int

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
type KeydraFlag int

const (
	KeydraFlagNew               KeydraFlag = 1
	KeydraFlagEncrypt           KeydraFlag = 2
	KeydraFlagTrace             KeydraFlag = 4
	KeydraFlagStateless         KeydraFlag = 8
	KeydraFlagRetry             KeydraFlag = 16
	KeydraFlagRatchet           KeydraFlag = 32
	KeydraFlagAuthorizePacket   KeydraFlag = 64
	KeydraFlagAuthorizeRequired KeydraFlag = 128
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

// Back to business.
// Packet interface
type KeydraPacket interface {
	setClientId(CiD []byte)
	setTransactionId(TxID []byte)
	setMessageType()
	setFlag()
	setAuthKey()

	calculateBodyLen()
}

// Datagram struct
type KeydraDatagram struct {
	// Implements
	KeydraPacket

	// We have a transaction ID and client ID and not a reimplementation of seq and ack
	// because at some stage down the line we may wish to add seq and ack as options,
	// and have client ID and TxID serve as IP:PORT (CiD:TxID) and have the options
	// hold SEQ and ACK for each CiD:TxID combo.
	TransactionID []byte
	ClientID      string

	// Flags
	Flags []byte // Array of bytes we'll convert to a number or something idk

	// Calculated Fields
	BodyLen   int
	HeaderLen int
}
