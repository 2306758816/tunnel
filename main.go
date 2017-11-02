package main

import (
	"flag"
	"log"
	"os"
	"sync"

	"github.com/ccsexyz/utils"
)

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	var pprof string
	var configfile string
	var cmdconfig config

	flag.StringVar(&cmdconfig.Type, "type", "server", "server type(local or server)")
	flag.IntVar(&cmdconfig.DataShard, "ds", 0, "set fec - datashard")
	flag.IntVar(&cmdconfig.ParityShard, "ps", 0, "set fec - parityshard")
	flag.StringVar(&cmdconfig.Localaddr, "l", "", "set local listen address")
	flag.StringVar(&cmdconfig.Remoteaddr, "r", "", "set remote server address")
	flag.BoolVar(&cmdconfig.NoHTTP, "nohttp", false, "disable http-obfs")
	flag.BoolVar(&cmdconfig.UDP, "udp", false, "use udp socket")
	flag.StringVar(&cmdconfig.Host, "host", "www.bing.com", "set the host of obfs")
	flag.IntVar(&cmdconfig.Expires, "expires", 60, "expiration time")
	flag.StringVar(&cmdconfig.Method, "method", "chacha20", "the method of encryption(chacha20, aes-*, rc4-md5, salsa20, none)")
	flag.StringVar(&cmdconfig.Password, "pass", "123", "pre-shared password")
	flag.IntVar(&cmdconfig.Mtu, "mtu", 1400, "set maximum transmission unit")
	flag.StringVar(&pprof, "pprof", "", "the listen address of pprof http server")
	flag.StringVar(&configfile, "c", "", "the path of config file")
	flag.BoolVar(&cmdconfig.Dummy, "dummy", false, "enable dummy socket")
	flag.BoolVar(&cmdconfig.UseMul, "usemul", false, "use multi-conn mode")
	flag.IntVar(&cmdconfig.MulConn, "mulconn", 0, "set the number of mulconn")
	flag.Parse()

	if len(os.Args) == 2 {
		configfile = os.Args[1]
	}

	if len(pprof) != 0 {
		utils.RunProfileHTTPServer(pprof)
	}

	configs, err := readConfig(configfile)
	if err != nil && !cmdconfig.valid() {
		log.Fatal(err)
	}
	if cmdconfig.valid() {
		checkConfig(&cmdconfig)
		configs = append(configs, &cmdconfig)
	}
	var wg sync.WaitGroup
	for _, c := range configs {
		wg.Add(1)
		go func(c *config) {
			defer wg.Done()
			c.print()
			switch c.Type {
			case "server":
				RunRemoteServer(c)
			default:
				RunLocalServer(c)
			}
		}(c)
	}
	wg.Wait()
}
