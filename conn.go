package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type halfCipher struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newHalfCipher(trafficSecret []byte) (*halfCipher, error) {
	key := hkdfExpandLabel(trafficSecret, "key", nil, 16)
	iv := hkdfExpandLabel(trafficSecret, "iv", nil, 12)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &halfCipher{aead: aead, iv: iv}, nil
}

func (hc *halfCipher) buildNonce() []byte {
	nonce := make([]byte, 12)
	copy(nonce, hc.iv)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], hc.seq)
	for i := range 8 {
		nonce[4+i] ^= seqBuf[i]
	}
	return nonce
}

type simpleTLSConn struct {
	raw     net.Conn
	in      *halfCipher
	out     *halfCipher
	handBuf []byte
}

func (c *simpleTLSConn) writeRecord(contentType byte, payload []byte) error {
	if c.out == nil || contentType == recordTypeChangeCipherSpec {
		header := []byte{contentType, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
		_, err := c.raw.Write(append(header, payload...))
		return err
	}

	innerPlaintext := append(append([]byte{}, payload...), contentType)
	cipherLen := len(innerPlaintext) + c.out.aead.Overhead()

	header := []byte{recordTypeApplicationData, 0x03, 0x03, byte(cipherLen >> 8), byte(cipherLen)}
	ciphertext := c.out.aead.Seal(nil, c.out.buildNonce(), innerPlaintext, header)
	c.out.seq++

	_, err := c.raw.Write(append(header, ciphertext...))
	return err
}

func (c *simpleTLSConn) readRecord() (byte, []byte, error) {
	for {
		var header [5]byte
		if _, err := io.ReadFull(c.raw, header[:]); err != nil {
			return 0, nil, err
		}
		recType := header[0]
		recLen := binary.BigEndian.Uint16(header[3:5])
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(c.raw, payload); err != nil {
			return 0, nil, err
		}

		if recType == recordTypeChangeCipherSpec {
			continue
		}

		if c.in == nil {
			return recType, payload, nil
		}
		if recType != recordTypeApplicationData {
			return 0, nil, fmt.Errorf("invalid plaintext: 0x%x", recType)
		}

		plain, err := c.in.aead.Open(nil, c.in.buildNonce(), payload, header[:])
		if err != nil {
			return 0, nil, fmt.Errorf("aead open failed: %w", err)
		}
		c.in.seq++

		for len(plain) > 0 && plain[len(plain)-1] == 0 {
			plain = plain[:len(plain)-1]
		}
		if len(plain) == 0 {
			return 0, nil, errors.New("empty TLS 1.3 plaintext")
		}
		return plain[len(plain)-1], plain[:len(plain)-1], nil
	}
}

func (c *simpleTLSConn) readHandshake() ([]byte, error) {
	for len(c.handBuf) < 4 {
		recType, data, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if recType != recordTypeHandshake {
			return nil, fmt.Errorf("expect handshake(0x16), but receive 0x%x", recType)
		}
		c.handBuf = append(c.handBuf, data...)
	}
	msgLen := int(c.handBuf[1])<<16 | int(c.handBuf[2])<<8 | int(c.handBuf[3])
	total := 4 + msgLen
	for len(c.handBuf) < total {
		recType, data, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if recType != recordTypeHandshake {
			return nil, fmt.Errorf("expect handshake(0x16), but receive 0x%x", recType)
		}
		c.handBuf = append(c.handBuf, data...)
	}
	msg := append([]byte(nil), c.handBuf[:total]...)
	c.handBuf = c.handBuf[total:]
	return msg, nil
}

func hkdfExtract(salt, ikm []byte) []byte {
	return computeHMAC(salt, ikm)
}

func computeHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	info = append(info, 0x01)
	return computeHMAC(secret, info)[:length]
}

func deriveSecret(secret []byte, label string, transcripthash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcripthash, 32)
}

func appendUint16(b []byte, v int) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint24(b []byte, v int) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}
