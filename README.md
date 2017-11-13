Name 
====

tunnel - a simple udp tunnel to help you improve your network environment.   

Synopsis
========

```
#./tunnel -type server -l 127.0.0.1:1080 -r 127.0.0.1:1194 -method chacha20 -pass password -mtu 1200 -ds 20 -ps 10 -expires 300
#./tunnel -type local  -l 127.0.0.1:1195 -r 127.0.0.1:1080 -method chacha20 -pass password -mtu 1200 -ds 20 -ps 10 -host www.zhihu.com -expires 300 -tls   
```

Features 
========

* turn udp traffic to tcp traffic  
* http obfuscating  
* tls obfuscating  
* support multiple encryption methods(chacha20/aes*/rc4-md5/salsa20/none)  
* forward error correction(copy from kcp-go)  
* aggregate multiple underlying connections to one udp connection  
* easy to install & build & use   

Installation
============

It is highly recommended to use [tunnel releases](https://github.com/ccsexyz/tunnel/releases).  

Note for Windows Users   
tunnel is dependent on winpcap.You should download and install it from [winpcap](https://www.winpcap.org/install/default.htm) first.

Note for Linux Users  
tunnel use raw-socket to receive and send tcp packets. root permission is required.

Note for Macos Users  
tunnel requires read permission for /dev/bpfx. so don't run tunnel as nobody user.   

Build 
=====

```  
$ go get -u -v github.com/ccsexyz/tunnel

# or 
$ go get github.com/ccsexyz/tunnel 
$ cd $GOPATH/src/github.com/ccsexyz/tunnel  
$ ./build.sh  
```  

Note for Windows 64bit Users

If you're trying to compile 64-bit tunnel(or google/gopacket) on Windows, you might have to do the crazy hijinks detailed at [compile gopacket on windows](http://stackoverflow.com/questions/38047858/compile-gopacket-on-windows-64bit)  

Usage
=====

```
$ ./tunnel -h
Usage of ./tunnel:
  -c string
    	the path of config file
  -ds int
    	set fec - datashard
  -expires int
    	expiration time (default 60)
  -host string
    	set the host of obfs (default "www.bing.com")
  -l string
    	set local listen address
  -method string
    	the method of encryption(chacha20, aes-*, rc4-md5, salsa20, none) (default "chacha20")
  -mtu int
    	set maximum transmission unit (default 1400)
  -mulconn int
    	set the number of mulconn
  -nodummy
    	disable dummy socket
  -nohttp
    	disable http-obfs
  -pass string
    	pre-shared password (default "123")
  -pprof string
    	the listen address of pprof http server
  -ps int
    	set fec - parityshard
  -r string
    	set remote server address
  -tls
    	enable tls-obfs
  -type string
    	server type(local or server) (default "server")
  -udp
    	use udp socket
  -usemul
    	use multi-conn mode
```

Author
=======

* ccsexyz  