package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/willf/bitset"

	"github.com/ccsexyz/utils"
)

type Conn struct {
	net.Conn
	*config
}

func (c *Conn) Read(b []byte) (n int, err error) {
	b2 := make([]byte, c.Mtu)
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
	defer func() {
		// log.Println(n, err)
	}()
	n2 := len(b) + c.Ivlen
	if n2 > c.Mtu {
		err = fmt.Errorf("buffer is too large")
		return
	}
	enc, err := utils.NewEncrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	b2 := make([]byte, c.Mtu)
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[c.Ivlen:], b)
	_, err = c.Conn.Write(b2[:n2])
	if err == nil {
		n = len(b)
	}
	return
}

// FecConn implements FEC decoder and encoder
type FecConn struct {
	net.Conn
	*config
	fecDecoder *fecDecoder
	fecEncoder *fecEncoder
	checker    *packetIDChecker
	pktid      uint64
	recovers   [][]byte
}

func (c *FecConn) doRead(b []byte) (n int, err error) {
	for n == 0 {
		for len(c.recovers) != 0 {
			r := c.recovers[0]
			c.recovers = c.recovers[1:]
			if len(r) < 2 {
				continue
			}
			sz := int(binary.LittleEndian.Uint16(r))
			if sz < 2 || sz > len(r) {
				continue
			}
			n = copy(b, r[2:sz])
			return
		}
		buf := make([]byte, c.Mtu)
		var num int
		num, err = c.Conn.Read(buf)
		if err != nil {
			return
		}
		f := c.fecDecoder.decodeBytes(buf)
		if f.flag == typeData {
			n = copy(b, buf[fecHeaderSizePlus2:num])
		}
		if f.flag == typeData || f.flag == typeFEC {
			c.recovers = c.fecDecoder.decode(f)
		}
	}
	return
}

func (c *FecConn) Read(b []byte) (n int, err error) {
	for {
		var nr int
		nr, err = c.doRead(b)
		if err != nil {
			return
		}
		if nr < 8 {
			continue
		}
		pktid := binary.BigEndian.Uint64(b[len(b)-8:])
		if c.checker.test(pktid) == false {
			continue
		}
		n = nr - 8
		return
	}
}

func (c *FecConn) Write(b []byte) (n int, err error) {
	blen := len(b)
	ext := b[:fecHeaderSizePlus2+blen+8]
	copy(ext[fecHeaderSizePlus2:fecHeaderSizePlus2+blen], b)
	pktid := atomic.AddUint64(&c.pktid, 1)
	binary.BigEndian.PutUint64(ext[fecHeaderSizePlus2+blen:], pktid)
	ecc := c.fecEncoder.encode(ext)

	_, err = c.Conn.Write(ext)
	if err != nil {
		return
	}

	for _, e := range ecc {
		_, err = c.Conn.Write(e)
		if err != nil {
			return
		}
	}

	n = blen
	return
}

const maxConv = 4096

type packetIDChecker struct {
	currHead  uint64
	oldIdsSet *bitset.BitSet
	curIdsSet *bitset.BitSet
	lock      sync.Mutex
}

func newPacketIDChecker() *packetIDChecker {
	p := new(packetIDChecker)
	p.oldIdsSet = bitset.New(maxConv)
	p.curIdsSet = bitset.New(maxConv)
	return p
}

func (p *packetIDChecker) testWithLock(id uint64) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.test(id)
}

func (p *packetIDChecker) test(id uint64) bool {
	if id > p.currHead+2*maxConv || id+maxConv < p.currHead {
		return false
	}
	if id < p.currHead {
		off := uint(id + maxConv - p.currHead)
		if p.oldIdsSet.Test(off) {
			return false
		}
		p.oldIdsSet.Set(off)
		return true
	}
	if id >= p.currHead && id < p.currHead+maxConv {
		off := uint(id - p.currHead)
		if p.curIdsSet.Test(off) {
			return false
		}
		p.curIdsSet.Set(off)
		return true
	}
	o := p.oldIdsSet.ClearAll()
	p.oldIdsSet = p.curIdsSet
	p.curIdsSet = o
	p.currHead += maxConv
	return p.test(id)
}
