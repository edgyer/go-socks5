package socks5

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	lAddr := l.Addr().(*net.TCPAddr)

	// request header
	header := Header{
		Version:   socks5Version,
		Command:   ConnectCommand,
		Reserved:  uint8(0),
		Address:   AddrSpec{
			FQDN: "",
			IP:  []byte{127, 0, 0, 1},
			Port: lAddr.Port,
		},
		addrType:ipv4Address,
	}

	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		_,payload, err := Parse(r)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(payload, []byte("ping")) {
			t.Fatalf("bad: %v", payload)
		}
		_,err = conn.Write([]byte("pong"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Load handlers
	s.Load()

	buf := bytes.NewBuffer(nil)
	buf.Write(header.Bytes())
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(header,buf,AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	lAddr := l.Addr().(*net.TCPAddr)
	header := Header{
		Version:   socks5Version,
		Command:   ConnectCommand,
		Reserved:  uint8(0),
		Address:   AddrSpec{
			FQDN: "",
			IP:  []byte{127, 0, 0, 1},
			Port: lAddr.Port,
		},
		addrType:ipv4Address,
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		_,payload, err := Parse(r)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(payload, []byte("ping")) {
			t.Fatalf("bad: %v", payload)
		}
		_,err = conn.Write([]byte("pong"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	//Load handlers
	s.Load()

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write(header.Bytes())

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(header,buf,AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
	}

	if !bytes.Equal(out[:4], expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}
