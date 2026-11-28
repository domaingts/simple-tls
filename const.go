package main

const (
	recordTypeChangeCipherSpec = 0x14
	recordTypeAlert           = 0x15
	recordTypeHandshake       = 0x16
	recordTypeApplicationData = 0x17

	hsClientHello         = 0x01
	hsServerHello         = 0x02
	hsEncryptedExtensions = 0x08
	hsCertificate         = 0x0b
	hsCertificateVerify   = 0x0f
	hsFinished            = 0x14
)
