package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net"

	"github.com/ccsexyz/utils"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func newConn(conn net.Conn, cfg *config) *Conn {
	c := &Conn{
		Conn:   &utils.CopyConn{Conn: conn},
		config: cfg,
		isaead: isAead(cfg.Method),
	}
	if c.isaead {
		c.pass = pbkdf(cfg.Password, "hello")
	}
	return c
}

type Conn struct {
	utils.Conn
	*config
	isaead bool
	pass   []byte
}

func isAead(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305":
		return true
	}
	return false
}

func (c *Conn) Read(b []byte) (n int, err error) {
	for {
		b2 := b
		n, err = c.Conn.Read(b2)
		if err != nil {
			return
		}
		if n > c.Mtu {
			continue
		}
		if !c.isaead {
			if n < c.Ivlen {
				continue
			}
			var dec utils.Decrypter
			dec, err = utils.NewDecrypter(c.Method, c.Password, b2[:c.Ivlen])
			if err != nil {
				return
			}
			dec.Decrypt(b, b2[c.Ivlen:n])
			n -= c.Ivlen
			return
		}
		aead, aerr := newAEADCipher(c.Method, c.pass)
		if aerr != nil {
			return 0, aerr
		}
		if n < aead.Overhead()+aead.NonceSize() {
			continue
		}
		nonce := b2[:aead.NonceSize()]
		// nonce := utils.GetBuf(aead.NonceSize())
		// defer utils.PutBuf(nonce)
		// nonce = nonce[:aead.NonceSize()]
		// copy(nonce, b2)
		b2, err = aead.Open(b[:0], nonce, b2[aead.NonceSize():n], nil)
		if err != nil {
			continue
		}
		n = len(b2)
		return
	}
}

func (c *Conn) aeadWrite(b []byte) (n int, err error) {
	aead, aerr := newAEADCipher(c.Method, c.pass)
	if aerr != nil {
		return 0, aerr
	}
	nonceSize := aead.NonceSize()
	if nonceSize+aead.Overhead()+len(b) > c.Mtu {
		err = fmt.Errorf("buffer is too large")
		return
	}
	buf := utils.GetBuf(len(b) + nonceSize + aead.Overhead())
	defer utils.PutBuf(buf)
	_, err = io.ReadFull(rand.Reader, buf[:nonceSize])
	if err != nil {
		return
	}
	out := aead.Seal(buf[nonceSize:nonceSize], buf[:nonceSize], b, nil)
	n, err = c.Conn.Write(buf[:len(out)+nonceSize])
	if err != nil {
		return
	}
	n = len(b)
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.isaead {
		n, err = c.aeadWrite(b)
		return
	}
	n2 := len(b) + c.Ivlen
	if n2 > c.Mtu {
		err = fmt.Errorf("buffer is too large")
		return
	}
	enc, err := utils.NewEncrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	b2 := utils.GetBuf(n2)
	defer utils.PutBuf(b2)
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[c.Ivlen:], b)
	_, err = c.Conn.Write(b2[:n2])
	if err == nil {
		n = len(b)
	}
	return
}

func pbkdf(key, salt string) []byte {
	return pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
}

func newAEADCipher(method string, pass []byte) (cipher.AEAD, error) {
	if method == "chacha20-poly1305" {
		return chacha20poly1305.New(pass[:chacha20poly1305.KeySize])
	}
	block, err := aes.NewCipher(pass[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
