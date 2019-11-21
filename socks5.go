package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socks5Version = uint8(5)
	socks4Version = uint8(4)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Enable socks4 support
	Socks4Support bool
}

type handler func(ctx context.Context, conn conn, req *Request)(err error)
// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
	handlers map[uint8]handler
}

// loads all the handler functions
func (s *Server) Load() {
	s.handlers = map[uint8]handler{
		BindCommand: s.handleBind,
		ConnectCommand: s.handleConnect,
		AssociateCommand: s.handleAssociate,
	}
}



// Header represents the SOCKS5/SOCKS4 header, it contains everything that is not payload
type Header struct {
	// Version of socks protocol for message
	Version          uint8
	// Socks Command "connect","bind","associate"
	Command          uint8
	// Reserved byte - TODO: expand for auth proxy project
	Reserved         uint8 //socks5 onnly
	// Address in socks message
	Address   AddrSpec
	// private stuff set when Header parsed
	addrType  uint8
	addrLen   int
	headerLen int
}

func (h Header) Bytes()(b []byte){
	b = append(b, h.Version)
	b = append(b, h.Command)
	bPort := []byte{0,0}
	binary.LittleEndian.PutUint16(bPort, uint16(h.Address.Port))
	if h.Version == socks4Version {
		b = append(b,bPort...)
		b = append(b,h.Address.IP...)
		return b
	}
	if h.Version == socks5Version {
		b = append(b,h.Reserved)
		b = append(b,h.AddrType())
		if h.AddrType() == fqdnAddress{
			fqdn := []byte(h.Address.FQDN)
			b = append(b,fqdn...)
		}else{
			b = append(b,h.Address.IP...)
		}
		b = append(b,bPort...)
		return b
	}
	return b
}

func (h Header) AddrType() uint8 {
	return h.addrType
}

func (h Header) AddrLen() int {
	return h.addrLen
}

func (h Header) HeaderLen() int {
	return h.headerLen
}

func Parse(r io.Reader) (hd Header,payload []byte, err error) {
	h := make([]byte,5)
	bufConn:=bufio.NewReader(r)
	if h, err = bufConn.Peek(5) ; err != nil {
		return hd,payload, fmt.Errorf("failed to get header: %v", err)
	}
	if h[0] != socks5Version && h[0] != socks4Version {
		return hd,payload, fmt.Errorf("unrecognized SOCKS version")
	}
	if h[1] != ConnectCommand && h[1] != BindCommand && h[1] != AssociateCommand {
		return hd,payload, fmt.Errorf("unrecognized command")
	}
	if h[1] == AssociateCommand && h[0] == socks4Version{
		return hd,payload, fmt.Errorf("wrong version for command")
	}
	addrType,addrLen,headerLen,err := getTypeAndLen(h[0],h[3],h[4])
	if err != nil {
		return hd,payload, err
	}
	reserved := uint8(0)
	if h[0] == socks5Version{
		reserved = h[2]
	}
	hd = Header{Version: h[0],Command:h[1],Reserved:reserved, addrType:addrType,addrLen:addrLen,headerLen:headerLen}
	bHeaderWithAddr := make([]byte,headerLen)
	if bHeaderWithAddr, err = bufConn.Peek(headerLen) ; err != nil {
		return hd,payload, fmt.Errorf("failed to get header address: %v", err)
	}
	hd.Addr(bHeaderWithAddr)
	if _,err := bufConn.Discard(headerLen) ; err != nil {
		return hd,payload, fmt.Errorf("failed to discard header: %v", err)
	}
	payload = make([]byte,4)
	if _,err := bufConn.Read(payload) ; err != nil {
		return hd,payload, fmt.Errorf("failed read payload: %v", err)
	}
	return hd, payload, nil
}

func getTypeAndLen(bVersionByte byte, bType byte,bLen byte)(addrType uint8, addrLen int, headerLen int, err error){
	baseLength := reqVersionLen + reqCommandLen + reqPortLen
	switch bType{
	case fqdnAddress:
		addrLen = int(bLen)
	case ipv4Address:
		addrLen = reqIPv4Addr
	case ipv6Address:
		addrLen = reqIPv6Addr
	default:
		return 0,0,0,unrecognizedAddrType
	}
	if bVersionByte == socks4Version {
		addrLen = reqIPv4Addr
	}else if bVersionByte == socks5Version{
		baseLength = baseLength + reqReservedLen + reqAddrTypeLen
	}else{
		return 0,0,0,unrecognizedAddrType
	}
	headerLen = baseLength+addrLen
	return bType,addrLen,headerLen,nil
}

func (h *Header) Addr(seeked []byte){
	req5Limiter:=map[uint8]func()(addr AddrSpec){
		ipv6Address:func ()(addr AddrSpec){
			addr.IP = seeked[reqAddrBytePos : reqAddrBytePos+reqIPv6Addr]
			p := seeked[h.HeaderLen() - reqPortLen : h.HeaderLen()]
			addr.Port = int(binary.BigEndian.Uint16(p))
			return
		},
		ipv4Address:func ()(addr AddrSpec) {
			addr.IP = seeked[reqAddrBytePos : reqAddrBytePos+reqIPv4Addr]
			if h.Version == socks4Version {
				p := seeked[req4PortBytePos : req4PortBytePos+reqPortLen]
				addr.Port = int(binary.BigEndian.Uint16(p))
				return
			}
			if h.Version == socks5Version {
				p := seeked[h.HeaderLen() - reqPortLen : h.HeaderLen()]
				addr.Port = int(binary.BigEndian.Uint16(p))
				return
			}
			return
		},
		fqdnAddress:func ()(addr AddrSpec){
			addr.FQDN = string(seeked[reqAddrBytePos:h.HeaderLen()-reqPortLen])
			p := seeked[h.HeaderLen() - reqPortLen : h.HeaderLen()]
			addr.Port = int(binary.BigEndian.Uint16(p))
			return
		},
	}
	h.Address = req5Limiter[h.AddrType()]()
}



// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {

	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config: conf,
	}

	// Ensure handlers are loaded
	server.Load()

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string, nl chan net.Listener) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	nl <- l
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	errChan := make(chan error)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(net.Conn) {
			if err := s.ServeConn(conn); err != nil {
				errChan <- err
			} else {
				errChan <- nil
			}
		}(conn)
		return <-errChan
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn)(err error) {

	// we dont treat this error here cause it might leave due to a different error and fail connection close
	defer conn.Close()
	// new buffer reader
	bufConn := bufio.NewReader(conn)

	// validate header
	header,_, err := Parse(bufConn)
	if err != nil {
		s.config.Logger.Printf("[ERR] socks: %v",err)
		return err
	}

	var authContext *AuthContext

	if header.Version == socks5Version {
		// Authenticate the connection
		authContext, err = s.authenticate(conn, bufConn)
		if err != nil {
			err = fmt.Errorf("authentication failed: %v", err)
			s.config.Logger.Printf("[ERR] socks: %v", err)
			return err
		}
	}

	request, err := NewRequest(header,bufConn,*authContext)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, header); err != nil {
				err = fmt.Errorf("failed to send reply: %v", err)
				s.config.Logger.Printf("[ERR] socks: %v", err)
				return err
			}
		}
		err = fmt.Errorf("failed to read destination address: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	if header.Version == socks5Version {
		request.AuthContext = authContext
	}

	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		s.config.Logger.Printf("[INFO] waiting for jumpbox to be available...")
		return err
	}

	//close the request
	if err := conn.Close(); err != nil{
		err = fmt.Errorf("failed closing the request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	return nil
}
