package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func runClient(addr, serverName string) error {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to dial tcp server: %w", err)
	}
	defer raw.Close()

	c := &simpleTLSConn{raw: raw}
	transcript := sha256.New()

	clientECDHPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	chMsg := buildClientHello(clientECDHPriv.PublicKey().Bytes(), serverName)
	transcript.Write(chMsg)
	if err := c.writeRecord(recordTypeHandshake, chMsg); err != nil {
		return fmt.Errorf("failed to send ClientHello: %w", err)
	}
	log.Println("[1/6] send ClientHello")

	shMsg, err := c.readHandshake()
	if err != nil {
		return fmt.Errorf("failed to read ServerHello: %w", err)
	}
	serverX25519Pub, err := parseServerHello(shMsg)
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello: %w", err)
	}
	transcript.Write(shMsg)

	peerPub, err := ecdh.X25519().NewPublicKey(serverX25519Pub)
	if err != nil {
		return fmt.Errorf("invalid server-side X25519 pub key: %w", err)
	}
	sharedSecret, err := clientECDHPriv.ECDH(peerPub)
	if err != nil {
		return fmt.Errorf("failed to compute ECDHE shared secret: %w", err)
	}

	zeros := make([]byte, 32)
	emptyHash := sha256.Sum256(nil)

	earlySecret := hkdfExtract(zeros, zeros)
	derived1 := deriveSecret(earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdfExtract(derived1, sharedSecret)

	chToShHash := transcript.Sum(nil)
	clientHsSecret := deriveSecret(handshakeSecret, "c hs traffic", chToShHash)
	serverHsSecret := deriveSecret(handshakeSecret, "s hs traffic", chToShHash)

	if c.in, err = newHalfCipher(serverHsSecret); err != nil {
		return err
	}
	if c.out, err = newHalfCipher(clientHsSecret); err != nil {
		return err
	}
	log.Println("[2/6] complete X25519 secret negotiation")

	eeMsg, err := c.readHandshake()
	if err != nil || eeMsg[0] != hsEncryptedExtensions {
		return fmt.Errorf("failed to read EncryptedExtensions: %w", err)
	}
	transcript.Write(eeMsg)

	certMsg, err := c.readHandshake()
	if err != nil {
		return fmt.Errorf("failed to read Certificate: %w", err)
	}
	serverCert, err := parseCertificate(certMsg)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}
	now := time.Now()
	if now.Before(serverCert.NotBefore) || now.After(serverCert.NotAfter) {
		return errors.New("server certificate is expired")
	}
	if err := serverCert.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("unmached hostname in certificate: %w", err)
	}
	serverEdPub, ok := serverCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("the pub key is not Ed25519 in server certificate")
	}
	transcript.Write(certMsg)
	log.Printf("[3/6] parse and verify the server certificate (DNSNames=%v ,ValidUntil=%s) ", serverCert.DNSNames, serverCert.NotAfter.Format(time.RFC3339))

	cvMsg, err := c.readHandshake()
	if err != nil {
		return fmt.Errorf("failed to read CertificateVerify: %w", err)
	}
	if err := verifyCertificateVerify(cvMsg, serverEdPub, transcript.Sum(nil)); err != nil {
		return err
	}
	transcript.Write(cvMsg)
	log.Println("[4/6] verify the CertificateVerify Ed25519 signature, server side is valid")

	sfMsg, err := c.readHandshake()
	if err != nil || len(sfMsg) != 36 || sfMsg[0] != hsFinished {
		return fmt.Errorf("failed to read Server Finished: %v", err)
	}
	serverFinKey := hkdfExpandLabel(serverHsSecret, "finished", nil, 32)
	expectedServerVerify := computeHMAC(serverFinKey, transcript.Sum(nil))
	if !hmac.Equal(sfMsg[4:], expectedServerVerify) {
		return errors.New("invalid Server Finished")
	}
	transcript.Write(sfMsg)

	chToSfHash := transcript.Sum(nil)
	derived2 := deriveSecret(handshakeSecret, "derived", emptyHash[:])
	masterSecret := hkdfExtract(derived2, zeros)
	clientAppSecret := deriveSecret(masterSecret, "c ap traffic", chToSfHash)
	serverAppSecret := deriveSecret(masterSecret, "s ap traffic", chToSfHash)

	if err := c.writeRecord(recordTypeChangeCipherSpec, []byte{0x01}); err != nil {
		return err
	}
	clientFinKey := hkdfExpandLabel(clientHsSecret, "finished", nil, 32)
	clientVerifyData := computeHMAC(clientFinKey, chToSfHash)
	cfMsg := wrapHandshake(hsFinished, clientVerifyData)

	fmt.Println("write client finshed")
	if err := c.writeRecord(recordTypeHandshake, cfMsg); err != nil {
		return fmt.Errorf("failed to send Client Finished: %w", err)
	}

	if c.in, err = newHalfCipher(serverAppSecret); err != nil {
		return err
	}
	if c.out, err = newHalfCipher(clientAppSecret); err != nil {
		return err
	}
	log.Println("[5/6] verify the Server Finished and Send Client Finished")

	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: hand-written-go-tls13-client\r\nConnection: close\r\n\r\n", serverName)
	if err := c.writeRecord(recordTypeApplicationData, []byte(httpReq)); err != nil {
		return fmt.Errorf("failed to send encrypted http request: %w", err)
	}

	log.Println("[6/6] send encrypted http request, wait for response...")
	for {
		recType, data, err := c.readRecord()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to read response: %w", err)
		}
		switch recType {
		case recordTypeApplicationData:
			fmt.Printf("\n--- receive HTTPS response ---\n%s-------------------------------\n", string(data))
		case recordTypeAlert:
			if len(data) == 2 && data[1] == 0x00 {
				log.Println("receive close_notify alter, close the connection gracefully")
				_ = c.writeRecord(recordTypeAlert, []byte{0x01, 0x00})
				return nil
			}
			return fmt.Errorf("receive TLS alter: level=%d desc=%d", data[0], data[1])
		case recordTypeHandshake:
			continue
		}
	}
	return nil
}

func buildClientHello(clientX25519Pub []byte, serverName string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)

	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	body = append(body, randomBytes...)

	sessionID := make([]byte, 32)
	_, _ = rand.Read(sessionID)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)

	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)

	var exts []byte

	if serverName != "" {
		nameBytes := []byte(serverName)
		var entry []byte
		entry = append(entry, 0x00)
		entry = appendUint16(entry, len(nameBytes))
		entry = append(entry, nameBytes...)
		var sniList []byte
		sniList = appendUint16(sniList, len(entry))
		sniList = append(sniList, entry...)
		exts = append(exts, 0x00, 0x00)
		exts = appendUint16(exts, len(sniList))
		exts = append(exts, sniList...)
	}

	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	exts = append(exts, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d)
	exts = append(exts, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07)

	exts = append(exts, 0x00, 0x33, 0x00, 0x26)
	exts = append(exts, 0x00, 0x24)
	exts = append(exts, 0x00, 0x1d, 0x00, 0x20)
	exts = append(exts, clientX25519Pub...)

	body = appendUint16(body, len(exts))
	body = append(body, exts...)
	return wrapHandshake(hsClientHello, body)
}

func parseServerHello(msg []byte) ([]byte, error) {
	if len(msg) < 4 || msg[0] != hsServerHello {
		return nil, errors.New("invalid ServerHello data")
	}
	b := msg[4:]
	if len(b) < 38 {
		return nil, errors.New("ServerHello too short")
	}
	pos := 2 + 32

	sessLen := int(b[pos])
	pos += 1 + sessLen
	if pos+5 > len(b) {
		return nil, errors.New("ServerHello out of bound")
	}

	cipherSuite := binary.BigEndian.Uint16(b[pos : pos+2])
	if cipherSuite != 0x1301 {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}
	pos += 3

	extTotal := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(b) {
		return nil, errors.New("invalid ServerHello length")
	}

	var isTLS13 bool
	var serverPub []byte
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(b[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		extData := b[pos+4 : pos+4+extLen]
		pos += 4 + extLen

		switch extType {
		case 0x002b:
			if len(extData) == 2 && binary.BigEndian.Uint16(extData) == 0x0304 {
				isTLS13 = true
			}
		case 0x0033:
			if len(extData) >= 4 {
				group := binary.BigEndian.Uint16(extData[0:2])
				kLen := int(binary.BigEndian.Uint16(extData[2:4]))
				if group == 0x001d && kLen == 32 && len(extData) == 4+kLen {
					serverPub = extData[4 : 4+kLen]
				}
			}
		}
	}
	if !isTLS13 {
		return nil, errors.New("unnegotiated TLS 1.3")
	}
	if len(serverPub) != 32 {
		return nil, errors.New("no X25519 pub key in ServerHello")
	}
	return serverPub, nil
}

func parseCertificate(msg []byte) (*x509.Certificate, error) {
	if len(msg) < 4 || msg[0] != hsCertificate {
		return nil, errors.New("invalid Certificate")
	}
	b := msg[4:]
	if len(b) < 1 {
		return nil, errors.New("Certificate is empty")
	}
	ctxLen := int(b[0])
	pos := 1 + ctxLen
	if pos+3 > len(b) {
		return nil, errors.New("lack certificate_list length")
	}
	listLen := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
	pos += 3
	if listLen == 0 || pos+3 > len(b) {
		return nil, errors.New("no certificate")
	}
	certLen := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
	pos += 3
	if pos+certLen > len(b) {
		return nil, errors.New("DER is too long")
	}
	return x509.ParseCertificate(b[pos : pos+certLen])
}

func verifyCertificateVerify(msg []byte, pubKey ed25519.PublicKey, transcriptHash []byte) error {
	if len(msg) < 8 || msg[0] != hsCertificateVerify {
		return errors.New("invalid CertificateVerify data")
	}
	b := msg[4:]
	sigAlg := binary.BigEndian.Uint16(b[0:2])
	if sigAlg != 0x0807 {
		return fmt.Errorf("unsupported signature algorithm: 0x%04x", sigAlg)
	}
	sigLen := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) != 4+sigLen {
		return errors.New("invalid CertificateVerify length")
	}
	sig := b[4 : 4+sigLen]

	var toVerify []byte
	toVerify = append(toVerify, bytes.Repeat([]byte{0x20}, 64)...)
	toVerify = append(toVerify, []byte("TLS 1.3, server CertificateVerify")...)
	toVerify = append(toVerify, 0x00)
	toVerify = append(toVerify, transcriptHash...)

	if !ed25519.Verify(pubKey, toVerify, sig) {
		return errors.New("failed to verify signature")
	}
	return nil
}
