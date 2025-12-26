package main

import "fmt"

type shadowPacket struct {
	// Source data
	sourceAddr []byte
	sourceMac  []byte

	// Destination data
	destAddr []byte
	destMac  []byte

	// Transaction
	proto string
	data  []byte
}

func (sp shadowPacket) getSourceAddrStr() string {
	return fmt.Sprintf("%d.%d.%d.%d", sp.sourceAddr[0], sp.sourceAddr[1], sp.sourceAddr[2], sp.sourceAddr[3])
}

func (sp shadowPacket) getDestAddrStr() string {
	return fmt.Sprintf("%d.%d.%d.%d", sp.destAddr[0], sp.destAddr[1], sp.destAddr[2], sp.destAddr[3])
}
