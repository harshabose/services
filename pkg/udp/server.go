package udp

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"net"
// 	"os"
// 	"sync"
// 	"time"
//
// 	"github.com/harshabose/mediapipe"
// 	"github.com/harshabose/tools/pkg/set"
// )
//
// type Server struct {
// 	source  *mediapipe.CanGenerateConsume[[]byte, []byte]
// 	clients set.Set[*net.UDPAddr]
//
// 	bind    *net.UDPConn
// 	timeout time.Duration
// 	pool    sync.Pool
//
// 	mux    sync.RWMutex
// 	once   sync.Once
// 	ctx    context.Context
// 	cancel context.CancelFunc
// }
//
// func (s *Server) listen() error {
// 	if err := s.bind.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
// 		return fmt.Errorf("error setting deadline (err=%w)", err)
// 	}
//
// 	buffp := s.pool.Get().(*[]byte)
// 	buff := *buffp
//
// 	n, sender, err := s.bind.ReadFromUDP(buff)
// 	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
// 		return nil
// 	}
// 	if err != nil {
// 		return fmt.Errorf("error while reading udp (err=%w)", err)
// 	}
//
// 	if s.unique(sender) {
//
// 	}
//
// }
//
// func (s *Server) read() {
//
// }
//
// func (s *Server) unique(addr *net.UDPAddr) bool {
// 	s.mux.RLock()
// 	defer s.mux.RUnlock()
//
// 	return !s.clients.ExistsIf(func(addr2 *net.UDPAddr) bool {
// 		return addr2.IP.Equal(addr.IP) && addr2.Port == addr.Port
// 	})
// }
//
// func (s *Server) add(addr *net.UDPAddr) {
//
// }
//
// func (s *Server) remove(addr *net.UDPAddr) {
// 	s.mux.Lock()
// 	defer s.mux.Unlock()
//
// 	s.clients.RemoveIf(func(addr2 *net.UDPAddr) bool {
// 		return addr2.IP.Equal(addr.IP) && addr2.Port == addr.Port
// 	})
// }
