package socks

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	//"strconv"
	"encoding/binary"
)

/*
socks5 protocol

initial

byte | 0  |   1    | 2 | ...... | n |
     |0x05|num auth|  auth methods  |


reply

byte | 0  |  1  |
     |0x05| auth|


username/password auth request

byte | 0  |  1         |          |     1 byte   |          |
     |0x01|username_len| username | password_len | password |

username/password auth reponse

byte | 0  | 1    |
     |0x01|status|

request

byte | 0  | 1 | 2  |   3    | 4 | .. | n-2 | n-1| n |
     |0x05|cmd|0x00|addrtype|      addr    |  port  |

response
byte |0   |  1   | 2  |   3    | 4 | .. | n-2 | n-1 | n |
     |0x05|status|0x00|addrtype|     addr     |  port   |

*/

// Socks5AuthRequired means socks5 server need auth or not

type Socks5Request struct {
	Target string
	Host   string
	Port   int
}

type Socks5Conn struct {
	// username
	Username string
	// password
	Password string
	//addr        string
	ClientConn net.Conn
}

// func NewSocks5Conn(client net.Conn) (err error) {

// }

// func (s5 *Socks5Conn) Serve() {
// 	defer s5.Close()

// 	if err := s5.handshake(); err != nil {
// 		log.Println(err)
// 		return
// 	}

// 	if err := s5.processRequest(); err != nil {
// 		log.Println(err)
// 		return
// 	}
// }

func (s5 *Socks5Conn) Parse() (req *Socks5Request, err error) {
	buf := make([]byte, 1)
	io.ReadFull(s5.ClientConn, buf)
	if buf[0] != socks5Version {
		return nil, fmt.Errorf("only socks5 support. got %s\n", buf[0])
	}

	if err = s5.handshake(); err != nil {
		log.Println(err)
		return
	}

	return s5.parseRequest()
}

func (s5 *Socks5Conn) handshake() error {
	// version has already readed by socksConn.Serve()
	// only process auth methods here

	buf := make([]byte, 258)

	// read auth methods
	n, err := io.ReadAtLeast(s5.ClientConn, buf, 1)
	if err != nil {
		return err
	}

	l := int(buf[0]) + 1
	if n < l {
		// read remains data
		n1, err := io.ReadFull(s5.ClientConn, buf[n:l])
		if err != nil {
			return err
		}
		n += n1
	}

	if s5.Username == "" {
		// no auth required
		s5.ClientConn.Write([]byte{0x05, 0x00})
		return nil
	}

	hasPassAuth := false
	var passAuth byte = 0x02

	// check auth method
	// only password(0x02) supported
	for i := 1; i < n; i++ {
		if buf[i] == passAuth {
			hasPassAuth = true
			break
		}
	}

	if !hasPassAuth {
		s5.ClientConn.Write([]byte{0x05, 0xff})
		return errors.New("no supported auth method")
	}

	err = s5.passwordAuth()
	return err
}

func (s5 *Socks5Conn) passwordAuth() error {
	buf := make([]byte, 32)

	// username/password required
	s5.ClientConn.Write([]byte{0x05, 0x02})
	n, err := io.ReadAtLeast(s5.ClientConn, buf, 2)
	if err != nil {
		return err
	}

	//log.Printf("%+v", buf[:n])

	// check auth version
	if buf[0] != 0x01 {
		return errors.New("unsupported auth version")
	}

	usernameLen := int(buf[1])

	p0 := 2
	p1 := p0 + usernameLen

	if n < p1 {
		n1, err := s5.ClientConn.Read(buf[n:])
		if err != nil {
			return err
		}
		n += n1
	}

	username := buf[p0:p1]
	passwordLen := int(buf[p1])

	p3 := p1 + 1
	p4 := p3 + passwordLen

	if n < p4 {
		n1, err := s5.ClientConn.Read(buf[n:])
		if err != nil {
			return err
		}
		n += n1
	}

	password := buf[p3:p4]

	// log.Printf("get username: %s, password: %s", username, password)

	if string(username) == s5.Username && string(password) == s5.Password {
		s5.ClientConn.Write([]byte{0x01, 0x00})
		return nil
	}

	// auth failed
	s5.ClientConn.Write([]byte{0x01, 0x01})

	return fmt.Errorf("wrong password")
}

func (s5 *Socks5Conn) parseRequest() (req *Socks5Request, err error) {
	buf := make([]byte, 258)

	// read header
	n, err := io.ReadAtLeast(s5.ClientConn, buf, 10)
	if err != nil {
		return
	}

	if buf[0] != socks5Version {
		err = fmt.Errorf("error version %d", buf[0])
		return
	}

	// command only support connect
	if buf[1] != cmdConnect {
		err = fmt.Errorf("unsupported command %d", buf[1])
		return
	}

	hlen := 0   // target address length
	host := ""  // target address
	msglen := 0 // header length

	switch buf[3] {
	case addrTypeIPv4:
		hlen = 4
	case addrTypeDomain:
		hlen = int(buf[4]) + 1
	case addrTypeIPv6:
		hlen = 16
	}

	msglen = 6 + hlen

	if n < msglen {
		// read remains header
		_, err = io.ReadFull(s5.ClientConn, buf[n:msglen])
		if err != nil {
			return
		}
	}

	// get target address
	addr := buf[4 : 4+hlen]
	if buf[3] == addrTypeDomain {
		host = string(addr[1:])
	} else {
		host = net.IP(addr).String()
	}

	// get target port
	port := binary.BigEndian.Uint16(buf[msglen-2 : msglen])

	// target address
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	return &Socks5Request{
		Target: target,
		Host:   host,
		Port:   int(port),
	}, nil
}

// ConnectSuccess replies user with connect success
// Check for io.EOF to see if client connection is already closed
func (s5 *Socks5Conn) ConnectSuccess() (err error) {
	_, err = s5.ClientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01})
	return
}

// Forward proxies the client connection through a server connection
// func (s5 *Socks5Conn) Forward(serverConn net.Conn) {

// 	c := make(chan int, 2)

// 	go func() {
// 		io.Copy(s5.clientConn, serverConn)
// 		c <- 1
// 	}()

// 	go func() {
// 		io.Copy(serverConn, s5.clientConn)
// 		c <- 1
// 	}()

// 	<-c
// }

// func (s5 *Socks5Conn) Close() {
// 	if s5.serverConn != nil {
// 		s5.serverConn.Close()
// 	}
// 	if s5.clientConn != nil {
// 		s5.clientConn.Close()
// 	}
// }
