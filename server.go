package main

import (
	"log"
	"net"

	"github.com/ccsexyz/kcp-go-raw"

	"github.com/ccsexyz/rawcon"
	"github.com/ccsexyz/utils"
)

// RunRemoteServer run the remote server
func RunRemoteServer(c *config) {
	raw := rawcon.Raw{
		Host:   c.Host,
		DSCP:   0,
		IgnRST: true,
		Mixed:  true,
		Dummy:  !c.NoDummy,
	}
	smtu := c.Mtu
	if c.Slice {
		c.Mtu = 65535
	}
	conn, err := kcpraw.ListenRAW(c.Localaddr, c.Password, c.UseMul, c.UDP, &raw)
	if err != nil {
		log.Fatal(err)
	}
	create := func(sconn *utils.SubConn) (conn net.Conn, rconn net.Conn, err error) {
		conn = sconn
		if c.Slice {
			conn = utils.NewSliceConn(sconn, smtu)
		}
		conn = newConn(conn, c)
		if c.DataShard != 0 && c.ParityShard != 0 {
			conn = utils.NewFecConn(conn, c.DataShard, c.ParityShard)
		}
		rconn, err = net.Dial("udp", c.Remoteaddr)
		if err == nil {
			log.Println("create tunnel from", conn.RemoteAddr(), "->", conn.LocalAddr(), "to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
		}
		return
	}
	ctx := &utils.UDPServerCtx{Expires: c.Expires, Mtu: c.Mtu}
	ctx.RunUDPServer(conn, create)
}
