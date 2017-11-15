package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"

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
	if c.isaead || c.Auth {
		c.pass = pbkdf(cfg.Password, "hello")
	}
	if c.Auth && !c.isaead {
		c.mac = hmac.New(md5.New, c.pass)
	}
	return c
}

type Conn struct {
	utils.Conn
	*config
	isaead  bool
	pass    []byte
	mac     hash.Hash
	macLock sync.Mutex
}

func isAead(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305":
		return true
	}
	return false
}

func (c *Conn) getMAC(message []byte) []byte {
	c.macLock.Lock()
	defer c.macLock.Unlock()
	c.mac.Write(message)
	messageMAC := c.mac.Sum(nil)
	c.mac.Reset()
	return messageMAC
}

func (c *Conn) checkMAC(message, messageMAC []byte) bool {
	return hmac.Equal(messageMAC, c.getMAC(message))
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
			if c.mac != nil {
				if n < c.mac.Size() {
					continue
				}
				message := b2[:n-c.mac.Size()]
				messageMAC := b2[n-c.mac.Size() : n]
				if !c.checkMAC(message, messageMAC) {
					continue
				}
				n -= c.mac.Size()
			}
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
	if c.mac != nil {
		n2 += c.mac.Size()
	}
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
	if c.mac != nil {
		mac := c.getMAC(b2[:c.Ivlen+len(b)])
		copy(b2[c.Ivlen+len(b):], mac)
	}
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
