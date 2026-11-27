package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
	"log"
	"math/big"
	"net"
	"time"
)

func serveTLS(raw net.Conn, certDER []byte, certPriv ed25519.PrivateKey) {
	defer raw.Close()
	c := &simpleTLSConn{raw: raw}

	transcript := sha256.New()

	recType, chMsg, err := c.readRecord()
	if err != nil || recType != recordTypeHandshake {
		log.Printf("failed to read ClientHello: %v", err)
		return
	}
	clientSessionID, clientX25519Pub, err := parseClientHello(chMsg)
	if err != nil {
		log.Printf("failed to parse ClientHello: %v", err)
		return
	}
	transcript.Write(chMsg)

	serverECDHPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("failed to generate X25519 key: %v", err)
		return
	}
	peerPub, err := ecdh.X25519().NewPublicKey(clientX25519Pub)
	if err != nil {
		log.Printf("invalid client X25519 pub key: %v", err)
		return
	}
	sharedSecret, err := serverECDHPriv.ECDH(peerPub)
	if err != nil {
		log.Printf("failed to compute the share key: %v", err)
		return
	}

	shMsg := buildServerHello(clientSessionID, serverECDHPriv.PublicKey().Bytes())
	transcript.Write(shMsg)
	if err := c.writeRecord(recordTypeHandshake, shMsg); err != nil {
		log.Printf("failed to send ServerHello: %v", err)
		return
	}

	if len(clientSessionID) > 0 {
		_ = c.writeRecord(recordTypeChangeCiperSpec, []byte{0x01})
	}

	zeros := make([]byte, 32)
	emptyHash := sha256.Sum256(nil)

	earlySecret := hkExtract(zeros, zeros)
	derived1 := deriveSecret(earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkExtract(derived1, sharedSecret)

	chToShHash := transcript.Sum(nil)
	clientHsSecret := deriveSecret(handshakeSecret, "c hs traffic", chToShHash)
	serverHsSecret := deriveSecret(handshakeSecret, "s hs traffic", chToShHash)

	if c.out, err = newHalfCipher(serverHsSecret); err != nil {
		return
	}
	if c.in, err = newHalfCipher(clientHsSecret); err != nil {
		return
	}

	if err := sendHandshake(c, transcript, hsEncryptedExtensions, []byte{0x00, 0x00}); err != nil {
		return
	}

	if err := sendHandshake(c, transcript, hsCertificate, buildCertificateBody(certDER)); err != nil {
		return
	}

	

}

func sendHandshake(c *simpleTLSConn, transcript hash.Hash, hsType byte, body []byte) error {
	msg := wrapHandshake(hsType, body)
	transcript.Write(msg)
	return c.writeRecord(recordTypeHandshake, msg)
}

func wrapHandshake(hsType byte, body []byte) []byte {
	n := len(body)
	msg := make([]byte, 4+n)
	msg[0] = hsType
	msg[1], msg[2], msg[3] = byte(n>>16), byte(n>>8), byte(n)
	copy(msg[4:], body)
	return msg
}

func parseClientHello(msg []byte) (sessionID []byte, x25519Pub []byte, err error) {
	if len(msg) < 4 || msg[0] != hsClientHello {
		return nil, nil, errors.New("invild ClientHello")
	}
	b := msg[4:]
	if len(b) < 35 {
		return nil, nil, errors.New("ClientHello is too short")
	}
	pos := 2 + 32

	sessLen := int(b[pos])
	pos++
	if pos+sessLen+2 > len(b) {
		return nil, nil, errors.New("out of bound when parse session_id")
	}
	sessionID = b[pos : pos+sessLen]
	pos += sessLen

	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(b) {
		return nil, nil, errors.New("out of bound when parse cipher_suites")
	}
	compLen := int(b[pos])
	pos += 1 + compLen
	if pos+2 > len(b) {
		return nil, nil, errors.New("lack extensions")
	}

	extTotal := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(b) {
		return nil, nil, errors.New("invalid extensions length")
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(b[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		extData := b[pos+4 : pos+4+extLen]
		pos += 4 + extLen

		if extType == 0x0033 && len(extData) >= 2 {
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			for p := 2; p+4 <= 2+listLen && p+4 <= len(extData); {
				group := binary.BigEndian.Uint16(extData[p : p+2])
				kLen := int(binary.BigEndian.Uint16(extData[p+2 : p+4]))
				if group == 0x001d && kLen == 32 && p+4+kLen <= len(extData) {
					return sessionID, extData[p+4 : p+4+kLen], nil
				}
				p += 4 + kLen
			}
		}
	}
	return nil, nil, errors.New("no X25519 pub key in key_share")
}

func buildServerHello(clientSessionID, serverX25519Pub []byte) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)

	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	body = append(body, randomBytes...)

	body = append(body, byte(len(clientSessionID)))
	body = append(body, clientSessionID...)

	body = append(body, 0x13, 0x01)
	body = append(body, 0x00)

	var exts []byte
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	exts = append(exts, 0x00, 0x33, 0x00, 0x24)
	exts = append(exts, 0x00, 0x1d, 0x00, 0x20)
	exts = append(exts, serverX25519Pub...)

	body = appendUint16(body, len(exts))
	body = append(body, exts...)
	return wrapHandshake(hsServerHello, body)
}

func buildCertificateBody(certDER []byte) []byte {
	var entry []byte
	entry = appendUint24(entry, len(certDER))
	entry = append(entry, certDER...)
	entry = append(entry, 0x00, 0x00)

	body := []byte{0x00}
	body = appendUint24(body, len(entry))
	body = append(body, entry...)
	return body
}

func buildCertificateVerifyBody(priv ed25519.PrivateKey, transcriptHash []byte) []byte {
	var toSign []byte
	toSign = append(toSign, bytes.Repeat([]byte{0x20}, 64)...)
	toSign = append(toSign, []byte("TLS 1.3, server CertificateVerify")...)
	toSign = append(toSign, 0x00)
	toSign = append(toSign, transcriptHash...)

	sig := ed25519.Sign(priv, toSign)
	var body []byte
	body = append(body, 0x08, 0x07)
	body = appendUint16(body, len(sig))
	body = append(body, sig...)
	return body
}

func generateSelfSignedCert() ([]byte, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	return der, priv, err
}
