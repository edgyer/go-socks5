package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)



const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3) // only avaliable in socks5
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)

	// common fields
	reqProtocolVersionBytePos = uint8(0) // proto version pos
	reqCommandBytePos         = uint8(1)
	reqAddrBytePos            = uint8(4)
	reqStartLen               = uint8(4)

	reqVersionLen  = 1
	reqCommandLen  = 1
	reqPortLen     = 2
	reqReservedLen = 1
	reqAddrTypeLen = 1
	reqIPv4Addr    = 4
	reqIPv6Addr    = 8
	reqFQDNAddr    = 249

	//position settings for socks4
	req4PortBytePos = uint8(2)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN (fully qualified domain name)
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// String() Sprints AddrSpec
func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Headers
	Headers Header
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(header Header, bufConn io.Reader,authContext AuthContext) (*Request, error) {
	addr := header.Address
	request := &Request{
		Headers: header,
		Version:  header.Version,
		Command:  header.Command,
		DestAddr: &addr,
		bufConn:  bufConn,
	}
	if authContext.IsActive() && header.Version != socks4Version{
		request.AuthContext = &authContext
	}
	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn conn)(err error){
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		nctx, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, req.Headers); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
			return fmt.Errorf("failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = nctx
		dest.IP = addr
	}
	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	if err := s.handlers[req.Command](ctx,conn,req);err != nil{
		return fmt.Errorf("request handling error: %v",err)
	}

	return nil
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn conn, req *Request)(err error) {
	// Check if this is allowed
	if nctx, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, req.Headers); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v blocked by rules", req.DestAddr)
	} else {
		ctx = nctx
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}

	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, req.Headers); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	//if err := sendReply(conn, successReply, addrSpecFromNetAddr(target.LocalAddr())); err != nil {
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	req.Headers.Address = bind
	if err := sendReply(conn, successReply, req.Headers); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}




// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, conn conn, req *Request)(err error) {
	// newContext
	// Check if this is allowed
	if nctx, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, req.Headers); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = nctx
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, req.Headers); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, conn conn, req *Request)(err error) {
	// Check if this is allowed
	if nctx, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure,req.Headers); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("associate to %v blocked by rules", req.DestAddr)
	} else {
		ctx = nctx
	}

	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, req.Headers); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, header Header) error {
	var msg []byte

		header.Command = resp
		msg=header.Bytes()

	_, err := w.Write(msg)
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
