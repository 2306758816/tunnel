package main

import (
	"log"
	"net"

	"github.com/ccsexyz/kcp-go-raw"

	"github.com/ccsexyz/rawcon"
	"github.com/ccsexyz/utils"
)

// RunLocalServer run the local client server
func RunLocalServer(c *config) {
	raw := rawcon.Raw{
		NoHTTP: c.NoHTTP,
		Host:   c.Host,
		DSCP:   0,
		IgnRST: true,
		Dummy:  !c.NoDummy,
		TLS:    c.TLS,
	}
	smtu := c.Mtu
	if c.Slice {
		c.Mtu = 65535
	}
	ctx := &utils.UDPServerCtx{
		Mtu:     c.Mtu,
		Expires: c.Expires,
	}
	conn, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		log.Fatal(err)
	}
	create := func(sconn *utils.SubConn) (conn net.Conn, rconn net.Conn, err error) {
		conn = sconn
		rconn, err = kcpraw.DialRAW(c.Remoteaddr, c.Password, c.MulConn, c.UDP, &raw)
		if err != nil {
			log.Println(err)
			return
		}
		if c.Slice {
			rconn = utils.NewSliceConn(rconn, smtu)
		}
		rconn = newConn(rconn, c)
		if c.DataShard != 0 && c.ParityShard != 0 {
			rconn = utils.NewFecConn(rconn, c.DataShard, c.ParityShard)
		}
		log.Println("create tunnel from", conn.RemoteAddr(), "->", conn.LocalAddr(), "to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
		return
	}
	ctx.RunUDPServer(conn, create)
}
