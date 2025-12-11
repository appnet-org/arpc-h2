// main_grpc_proxy.go
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	"github.com/appnet-org/arpc/pkg/logging"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/peer"
)

//====================
// Config & State
//====================

// Config holds the proxy configuration.
type Config struct {
	Ports      []int
	TargetAddr string
}

// DefaultConfig returns the default proxy configuration.
func DefaultConfig() *Config {
	targetAddr := os.Getenv("TARGET_ADDR")
	if targetAddr == "" {
		targetAddr = "" // Empty by default - use iptables interception
	}

	return &Config{
		Ports:      []int{15002, 15006},
		TargetAddr: targetAddr,
	}
}

// ProxyState holds shared proxy state.
type ProxyState struct {
	// Default backend address if SO_ORIGINAL_DST is not available.
	targetAddr string

	// Map: client remote addr string ("ip:port") -> original destination ("ip:port").
	connTargets sync.Map

	// Connection pool: backend target ("ip:port") -> *grpc.ClientConn.
	connPool sync.Map
}

//====================
// Logging config
//====================

func getLoggingConfig() *logging.Config {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "debug"
	}

	format := os.Getenv("LOG_FORMAT")
	if format == "" {
		format = "console"
	}

	return &logging.Config{
		Level:  level,
		Format: format,
	}
}

//====================
// SO_ORIGINAL_DST helpers
//====================

// getOriginalDestination retrieves the original destination address for a TCP
// connection that was redirected by iptables. Returns the address and true if
// available.
func getOriginalDestination(conn net.Conn) (string, bool) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", false
	}

	file, err := tcpConn.File()
	if err != nil {
		logging.Debug("Failed to get file from connection", zap.Error(err))
		return "", false
	}
	defer file.Close()

	fd := file.Fd()

	// Try to get the original destination using SO_ORIGINAL_DST
	return getOriginalDestinationIPv4(fd)
}

// getOriginalDestinationIPv4 retrieves the original destination for IPv4 connections.
func getOriginalDestinationIPv4(fd uintptr) (string, bool) {
	// For IPv4, SO_ORIGINAL_DST returns a sockaddr_in structure
	// Size of sockaddr_in: family (2) + port (2) + addr (4) + zero padding (8) = 16 bytes
	var sockaddr [128]byte
	size := uint32(len(sockaddr))

	// SO_ORIGINAL_DST is at IPPROTO_IP level, not SOL_SOCKET
	// This socket option is set by iptables REDIRECT target
	err := getSockopt(int(fd), syscall.IPPROTO_IP, unix.SO_ORIGINAL_DST, unsafe.Pointer(&sockaddr[0]), &size)
	if err != nil {
		logging.Debug("Failed to get SO_ORIGINAL_DST", zap.Error(err))
		return "", false
	}

	// Parse sockaddr_in: [family(2)][port(2)][addr(4)][...]
	if size < 8 {
		return "", false
	}

	family := binary.LittleEndian.Uint16(sockaddr[0:2])
	if family != syscall.AF_INET {
		return "", false
	}

	port := binary.BigEndian.Uint16(sockaddr[2:4])
	ip := net.IPv4(sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7])

	return fmt.Sprintf("%s:%d", ip.String(), port), true
}

// getSockopt performs getsockopt syscall.
func getSockopt(s, level, name int, val unsafe.Pointer, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(vallen)),
		0,
	)
	if e1 != 0 {
		err = e1
	}
	return
}

//====================
// rawCodec for opaque gRPC messages
//====================

type rawCodec struct{}

func (rawCodec) Name() string { return "proxy" }

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return nil, fmt.Errorf("rawCodec expects []byte, got %T", v)
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	if bp, ok := v.(*[]byte); ok {
		*bp = append((*bp)[:0], data...)
		return nil
	}
	return fmt.Errorf("rawCodec expects *[]byte, got %T", v)
}

func init() {
	// Register codec so that content-type negotiation can find it if needed.
	encoding.RegisterCodec(rawCodec{})
}

//====================
// Listener wrapper to capture original dst
//====================

type originalDstListener struct {
	net.Listener
	state *ProxyState
}

func (l *originalDstListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	remote := c.RemoteAddr().String()

	// If a global target is configured, we do not need per-connection original dst.
	if l.state.targetAddr == "" {
		if orig, ok := getOriginalDestination(c); ok {
			l.state.connTargets.Store(remote, orig)
			logging.Debug("Recorded original destination",
				zap.String("client", remote),
				zap.String("target", orig))
		} else {
			logging.Debug("No SO_ORIGINAL_DST, will fall back to TARGET_ADDR if set",
				zap.String("client", remote))
		}
	}

	return c, nil
}

//====================
// Backend target + connection helpers
//====================

func (s *ProxyState) getBackendTarget(ctx context.Context) (string, error) {
	// If TARGET_ADDR is set, always use it.
	if s.targetAddr != "" {
		return s.targetAddr, nil
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "", fmt.Errorf("no peer info in context")
	}

	remote := p.Addr.String()
	if v, ok := s.connTargets.Load(remote); ok {
		if target, ok2 := v.(string); ok2 && target != "" {
			return target, nil
		}
	}

	return "", fmt.Errorf("no original destination for peer %s", remote)
}

// getClientConn returns (or creates) a shared *grpc.ClientConn for a target.
func (s *ProxyState) getClientConn(target string) (*grpc.ClientConn, error) {
	if v, ok := s.connPool.Load(target); ok {
		if cc, ok2 := v.(*grpc.ClientConn); ok2 {
			return cc, nil
		}
	}

	cc, err := grpc.Dial(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		return nil, err
	}

	actual, loaded := s.connPool.LoadOrStore(target, cc)
	if loaded {
		// Another goroutine won the race; close ours and use theirs.
		_ = cc.Close()
		if c, ok := actual.(*grpc.ClientConn); ok {
			return c, nil
		}
		return nil, fmt.Errorf("connection pool corrupted for target %s", target)
	}

	return cc, nil
}

//====================
// Stream handler (UnknownServiceHandler)
//====================

func (s *ProxyState) streamHandler(srv interface{}, ss grpc.ServerStream) error {
	fullMethod, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return fmt.Errorf("failed to get full method name")
	}

	ctx := ss.Context()

	target, err := s.getBackendTarget(ctx)
	if err != nil {
		logging.Error("Failed to resolve backend target", zap.Error(err))
		return err
	}

	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		logging.Debug("Proxy starting gRPC stream",
			zap.String("method", fullMethod),
			zap.String("client", p.Addr.String()),
			zap.String("backend", target),
		)
	} else {
		logging.Debug("Proxy starting gRPC stream (no peer addr)",
			zap.String("method", fullMethod),
			zap.String("backend", target),
		)
	}

	cc, err := s.getClientConn(target)
	if err != nil {
		logging.Error("Failed to get backend conn", zap.String("target", target), zap.Error(err))
		return err
	}

	// Bidirectional stream description: support all RPC types.
	desc := &grpc.StreamDesc{
		StreamName:    "proxy",
		ClientStreams: true,
		ServerStreams: true,
	}

	clientStream, err := cc.NewStream(ctx, desc, fullMethod)
	if err != nil {
		logging.Error("Failed to create backend stream",
			zap.String("target", target),
			zap.String("method", fullMethod),
			zap.Error(err))
		return err
	}

	errCh := make(chan error, 2)

	// Client -> Backend
	go func() {
		for {
			var in []byte
			if err := ss.RecvMsg(&in); err != nil {
				if err == io.EOF {
					logging.Debug("Client -> Backend stream EOF",
						zap.String("method", fullMethod),
						zap.String("backend", target),
					)
					_ = clientStream.CloseSend()
					errCh <- nil
				} else {
					logging.Debug("Client -> Backend RecvMsg error",
						zap.String("method", fullMethod),
						zap.String("backend", target),
						zap.Error(err),
					)
					errCh <- err
				}
				return
			}
			logging.Debug("Proxy hooked gRPC message: client -> backend",
				zap.String("method", fullMethod),
				zap.String("backend", target),
				zap.Int("msg_size", len(in)),
			)

			if err := clientStream.SendMsg(in); err != nil {
				logging.Debug("Client -> Backend SendMsg error",
					zap.String("method", fullMethod),
					zap.String("backend", target),
					zap.Error(err),
				)
				errCh <- err
				return
			}
		}
	}()

	// Backend -> Client
	go func() {
		for {
			var in []byte
			if err := clientStream.RecvMsg(&in); err != nil {
				if err == io.EOF {
					logging.Debug("Backend -> Client stream EOF",
						zap.String("method", fullMethod),
						zap.String("backend", target),
					)
					errCh <- nil
				} else {
					logging.Debug("Backend -> Client RecvMsg error",
						zap.String("method", fullMethod),
						zap.String("backend", target),
						zap.Error(err),
					)
					errCh <- err
				}
				return
			}

			// ADD: this log means you have received a *complete gRPC message* from the backend
			logging.Debug("Proxy hooked gRPC message: backend -> client",
				zap.String("method", fullMethod),
				zap.String("backend", target),
				zap.Int("msg_size", len(in)),
			)

			if err := ss.SendMsg(in); err != nil {
				logging.Debug("Backend -> Client SendMsg error",
					zap.String("method", fullMethod),
					zap.String("backend", target),
					zap.Error(err),
				)
				errCh <- err
				return
			}
		}
	}()

	// Wait for one side to finish with an error or both sides to finish cleanly.
	var firstErr error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil && firstErr == nil {
			firstErr = e
		}
	}

	if firstErr == nil {
		logging.Debug("Proxy completed gRPC stream",
			zap.String("method", fullMethod),
			zap.String("backend", target),
		)
	} else {
		logging.Debug("Proxy gRPC stream finished with error",
			zap.String("method", fullMethod),
			zap.String("backend", target),
			zap.Error(firstErr),
		)
	}

	return firstErr
}

//====================
// Server bootstrap
//====================

func startGRPCProxyServers(config *Config, state *ProxyState) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(config.Ports))

	for _, port := range config.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if err := runGRPCProxyServer(p, state); err != nil {
				errCh <- fmt.Errorf("gRPC proxy server on port %d failed: %w", p, err)
			}
		}(port)
	}

	wg.Wait()
	close(errCh)

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func runGRPCProxyServer(port int, state *ProxyState) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}
	defer lis.Close()

	logging.Info("gRPC-aware proxy listening",
		zap.Int("port", port),
		zap.String("targetFallback", state.targetAddr))

	odl := &originalDstListener{
		Listener: lis,
		state:    state,
	}

	server := grpc.NewServer(
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(state.streamHandler),
	)

	return server.Serve(odl)
}

//====================
// Shutdown handling
//====================

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logging.Info("Shutting down gRPC-aware proxy...")
}

//====================
// main
//====================

func main() {
	// Optional flag: override ports with comma-separated list if you like; for now keep ports unchanged.
	_ = flag.CommandLine // placeholder if you later add flags
	flag.Parse()

	if err := logging.Init(getLoggingConfig()); err != nil {
		panic(fmt.Sprintf("Failed to initialize logging: %v", err))
	}

	logging.Info("Starting gRPC-aware proxy on :15002 and :15006...")

	config := DefaultConfig()

	state := &ProxyState{
		targetAddr: config.TargetAddr,
	}

	logging.Info("Proxy target configured",
		zap.String("targetFallback", state.targetAddr))

	if err := startGRPCProxyServers(config, state); err != nil {
		logging.Fatal("Failed to start gRPC proxy servers", zap.Error(err))
	}

	waitForShutdown()
}
