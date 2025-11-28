package tcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// mockSuper implements mediapipe.CanGenerateConsume[[]byte, []byte]
// using channels for deterministic testing.
// Generate pulls from genCh; Consume pushes into consCh.
type mockSuper struct {
	genCh  chan []byte
	consCh chan []byte
}

func newMockSuper() *mockSuper {
	return &mockSuper{
		genCh:  make(chan []byte, 10),
		consCh: make(chan []byte, 10),
	}
}

func (m *mockSuper) Generate() ([]byte, error) {
	// Block until data is available or timeout via context in test side
	b := <-m.genCh
	return b, nil
}

func (m *mockSuper) Consume(payload []byte) error {
	m.consCh <- payload
	return nil
}

func getListenerPort(t *testing.T, s *Server) int {
	t.Helper()
	addr := s.l.Addr().(*net.TCPAddr)
	return addr.Port
}

func dialLocal(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	return conn
}

// func TestServer_ClientToSuper(t *testing.T) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
// 	defer cancel()
//
// 	sup := newMockSuper()
//
// 	s, err := NewServer(ctx, sup, 0)
// 	if err != nil {
// 		t.Fatalf("NewServer error: %v", err)
// 	}
// 	defer s.Close()
//
// 	port := getListenerPort(t, s)
// 	conn := dialLocal(t, port)
// 	defer conn.Close()
//
// 	want := []byte("hello-from-client")
// 	if _, err := conn.Write(want); err != nil {
// 		t.Fatalf("client write failed: %v", err)
// 	}
//
// 	select {
// 	case got := <-sup.consCh:
// 		fmt.Printf("got: %s\n", got)
// 		if string(got) != string(want) {
// 			t.Fatalf("Consume got %q, want %q", string(got), string(want))
// 		}
// 	case <-ctx.Done():
// 		t.Fatalf("timeout waiting for server to deliver client payload to super: %v", ctx.Err())
// 	}
// }
//
// func TestServer_SuperToClient(t *testing.T) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()
//
// 	sup := newMockSuper()
//
// 	s, err := NewServer(ctx, sup, 0)
// 	if err != nil {
// 		t.Fatalf("NewServer error: %v", err)
// 	}
// 	defer s.Close()
//
// 	port := getListenerPort(t, s)
// 	conn := dialLocal(t, port)
// 	defer conn.Close()
//
// 	want := []byte("hello-from-super")
//
// 	// Send data from super towards client
// 	time.Sleep(1 * time.Second)
// 	select {
// 	case sup.genCh <- want:
// 		fmt.Println("sent")
// 	case <-ctx.Done():
// 		t.Fatalf("timeout enqueueing super payload: %v", ctx.Err())
// 	}
//
// 	buf := make([]byte, len(want))
// 	if _, err := ioReadFullWithDeadline(conn, buf, 5*time.Second); err != nil {
// 		t.Fatalf("client read failed: %v", err)
// 	}
//
// 	fmt.Printf("got %s\n", string(buf))
// 	if string(buf) != string(want) {
// 		t.Fatalf("client got %q, want %q", string(buf), string(want))
// 	}
// }
//
// func TestServer_Close_ShutsDown(t *testing.T) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
//
// 	sup := newMockSuper()
// 	s, err := NewServer(context.Background(), sup, 0)
// 	if err != nil {
// 		t.Fatalf("NewServer error: %v", err)
// 	}
//
// 	// Close should cancel Done
// 	if err := s.Close(); err != nil {
// 		t.Fatalf("server close returned error: %v", err)
// 	}
//
// 	select {
// 	case <-s.Done():
// 		// ok
// 	case <-ctx.Done():
// 		t.Fatalf("timeout waiting for server Done after Close()")
// 	}
// }

// ioReadFullWithDeadline reads exactly len(buf) bytes from conn with a deadline.
func ioReadFullWithDeadline(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// // Additional tests for multi-client scenarios
// func TestServer_SuperToMultipleClients(t *testing.T) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
//
// 	sup := newMockSuper()
//
// 	s, err := NewServer(ctx, sup, 0)
// 	if err != nil {
// 		t.Fatalf("NewServer error: %v", err)
// 	}
// 	defer s.Close()
//
// 	port := getListenerPort(t, s)
// 	c1 := dialLocal(t, port)
// 	defer c1.Close()
// 	c2 := dialLocal(t, port)
// 	defer c2.Close()
//
// 	want := []byte("broadcast")
//
// 	// Enqueue payload to super; server should broadcast to all connected clients
// 	select {
// 	case sup.genCh <- want:
// 	case <-ctx.Done():
// 		t.Fatalf("timeout enqueueing super payload: %v", ctx.Err())
// 	}
//
// 	buf1 := make([]byte, len(want))
// 	if _, err := ioReadFullWithDeadline(c1, buf1, 3*time.Second); err != nil {
// 		t.Fatalf("client1 read failed: %v", err)
// 	}
//
// 	fmt.Printf("got1: %s\n", string(buf1))
//
// 	buf2 := make([]byte, len(want))
// 	if _, err := ioReadFullWithDeadline(c2, buf2, 3*time.Second); err != nil {
// 		t.Fatalf("client2 read failed: %v", err)
// 	}
//
// 	fmt.Printf("got2: %s\n", string(buf2))
//
// 	if string(buf1) != string(want) {
// 		t.Fatalf("client1 got %q, want %q", string(buf1), string(want))
// 	}
// 	if string(buf2) != string(want) {
// 		t.Fatalf("client2 got %q, want %q", string(buf2), string(want))
// 	}
// }

func TestServer_MultipleClientsToSuper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sup := newMockSuper()

	s, err := NewServer(ctx, sup, 0)
	if err != nil {
		t.Fatalf("NewServer error: %v", err)
	}
	defer s.Close()

	port := getListenerPort(t, s)
	c1 := dialLocal(t, port)
	defer c1.Close()
	c2 := dialLocal(t, port)
	defer c2.Close()

	p1 := []byte("from-client-1")
	p2 := []byte("from-client-2")

	// Write from both clients (order may vary at server)
	if _, err := c1.Write(p1); err != nil {
		t.Fatalf("client1 write failed: %v", err)
	}
	if _, err := c2.Write(p2); err != nil {
		t.Fatalf("client2 write failed: %v", err)
	}

	// Collect two payloads consumed by super (order-insensitive)
	got := make(map[string]bool)

	for i := 0; i < 2; i++ {
		select {
		case b := <-sup.consCh:
			got[string(b)] = true
			fmt.Printf("got: %s\n", string(b))
		case <-ctx.Done():
			t.Fatalf("timeout waiting for super to receive client payloads: %v", ctx.Err())
		}
	}

	if !got[string(p1)] || !got[string(p2)] {
		t.Fatalf("super did not receive all payloads. got=%v", got)
	}
}
