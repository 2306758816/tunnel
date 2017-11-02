package main

import (
	"fmt"

	"github.com/ccsexyz/utils"
)

type Conn struct {
	utils.Conn
	*config
	rbuf []byte
	wbuf []byte
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.rbuf == nil {
		c.rbuf = make([]byte, c.Mtu)
	}
	b2 := c.rbuf
	for {
		n, err = c.Conn.Read(b2)
		if err != nil {
			return
		}
		if n <= c.Ivlen || n > c.Mtu {
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
}

func (c *Conn) Write(b []byte) (n int, err error) {
	n2 := len(b) + c.Ivlen
	if n2 > c.Mtu {
		err = fmt.Errorf("buffer is too large")
		return
	}
	enc, err := utils.NewEncrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	if c.wbuf == nil {
		c.wbuf = make([]byte, c.Mtu)
	}
	b2 := c.wbuf
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[c.Ivlen:], b)
	_, err = c.Conn.Write(b2[:n2])
	if err == nil {
		n = len(b)
	}
	return
}
