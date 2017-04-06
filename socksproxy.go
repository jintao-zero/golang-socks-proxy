package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io"
	"net"
	"os"
	"strconv"
	"errors"
	"flag"
)

func handleVerMethodSelectMsg(srcConn net.Conn) error {
	var buffer [1024]byte
	_, err := srcConn.Read(buffer[:])
	if err != nil {
		return err
	}
	//1. version identifier/method selection message
	/*
	   +----+----------+----------+
	   |VER | NMETHODS | METHODS  |
	   +----+----------+----------+
	   | 1  |    1     | 1 to 255 |
	   +----+----------+----------+
	*/
	var ver = buffer[0]
	var nMethods = buffer[1]
	var methods = buffer[2 : nMethods+2]
	log.Debug(ver, nMethods, methods)
	/*
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/
	var resp = []byte{0x05, 0x00} // VER(0x05), METHOD(X'00') NO AUTHENTICATION REQUIRED
	_, err = srcConn.Write(resp)
	if err != nil {
		return err
	}
	return nil
}

func handleSocksRequest(srcConn net.Conn) (net.Conn, error ){
	var buffer [1024]byte
	if _, err := srcConn.Read(buffer[:]); err != nil {
		return nil, err
	}
	/*
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	var ver = buffer[0]
	_ = ver
	var cmd = buffer[1]
	// rsv := buffer[2]
	aTyp := buffer[3]
	var dstPort []byte
	var dstIp net.IP
	switch aTyp {
	case 0x01:
		dstIp = net.IP(buffer[4:8])
		dstPort = buffer[8 : 8+2]
	case 0x03:
		domainNameLen := buffer[4:5][0]
		domainName := buffer[5 : 5+domainNameLen]
		dstPort = buffer[5+domainNameLen: 5+domainNameLen+2]
		ipAddr, err := net.ResolveIPAddr("", string(domainName))
		if err != nil {
			return nil, err
		}
		log.Debug(string(domainName), ipAddr, binary.BigEndian.Uint16(dstPort))
		dstIp = ipAddr.IP
	case 0x04:
		dstIp = buffer[4:20]
		dstPort = buffer[20:22]
	}
	if cmd == 0x01 {
		dstConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   dstIp,
			Port: int(binary.BigEndian.Uint16(dstPort)),
		})
		if err != nil {
			return nil, err
		}
		var b bytes.Buffer
		b.Write([]byte{0x05}) //VER
		b.Write([]byte{0x00}) //REP
		b.Write([]byte{0x00}) //RSV
		b.Write([]byte{0x01}) //ATYP
		localHost, localPort, err := net.SplitHostPort(dstConn.LocalAddr().String())
		b.Write(net.ParseIP(localHost).To4()) // BND.ADDR
		localPortNum, _ := strconv.Atoi(localPort)
		var portBytes [2]byte
		binary.BigEndian.PutUint16(portBytes[:], uint16(localPortNum))
		b.Write(portBytes[:]) // BND.PORT
		_, err = srcConn.Write(b.Bytes())
		if err != nil {
			return nil, err
		}
		return dstConn,nil
	} else {
		return nil, errors.New(fmt.Sprintf("%s:%d", "unsupported cmd", cmd))
	}
}

func handleConn(srcConn net.Conn) {
	defer srcConn.Close()
	if err := handleVerMethodSelectMsg(srcConn); err != nil {
		log.Warn(err)
		return
	}
	dstConn, err := handleSocksRequest(srcConn);
	if err != nil {
		log.Warn(err)
		return
	}
	defer dstConn.Close()
	// start to forward
	go io.Copy(srcConn, dstConn)
	io.Copy(dstConn, srcConn)
}

var bind = flag.String("bind", ":1080", "socks proxy listen ip:port on")
func main() {
	flag.Parse()
	// set log
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	l, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Panic(err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Panic(err)
			return
		}
		go handleConn(conn)
	}
}
