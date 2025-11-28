package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/harshabose/mediapipe"
	"github.com/harshabose/mediapipe/pkg/consumers"
	"github.com/harshabose/mediapipe/pkg/generators"
	"github.com/harshabose/tools/pkg/multierr"
)

type Server struct {
	l    *net.TCPListener
	port uint16

	readers *mediapipe.MultiReader2[[]byte, []byte]
	writers *mediapipe.MultiWriter2[[]byte, []byte]

	pipe mediapipe.Pipe[[]byte, []byte]

	wg     sync.WaitGroup
	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
}

func NewServer(ctx context.Context, super mediapipe.CanGenerateConsume[[]byte, []byte], port uint16) (*Server, error) {
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), port)))
	if err != nil {
		return nil, err
	}

	ctx2, cancel2 := context.WithCancel(ctx)

	readers := mediapipe.NewMultiReader2[[]byte, []byte](ctx2, 10)
	writers := mediapipe.NewMultiWriter2[[]byte, []byte](ctx2, 10)

	pipe := mediapipe.NewAnyDuplexPipe[[]byte, []byte](ctx2,
		mediapipe.NewIdentityReaderWriter[[]byte](mediapipe.NewIdentityAnyReader(super), mediapipe.NewIdentityAnyWriter(super)),
		mediapipe.NewIdentityReaderWriter[[]byte](readers, writers),
	)

	s := &Server{
		l:       l,
		port:    port,
		readers: readers,
		writers: writers,
		pipe:    pipe,
		ctx:     ctx2,
		cancel:  cancel2,
	}

	s.pipe.Start()

	go s.start()
	return s, nil
}

func (s *Server) Done() <-chan struct{} {
	done := make(chan struct{})

	go func() {
		defer close(done)

		select {
		case <-s.ctx.Done():
		case <-s.pipe.Done():
		}
	}()

	return done
}

func (s *Server) start() {
	s.wg.Add(1)
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.pipe.Done():
			return
		default:
			conn, err := s.l.AcceptTCP()
			if err != nil {
				fmt.Printf("error while serving tcp (port=%d). err = %v\n", s.port, err)
				return
			}

			go s.serve(conn)
		}
	}
}

func (s *Server) serve(conn net.Conn) {
	defer fmt.Println("closed")
	s.wg.Add(1)
	defer s.wg.Done()

	defer conn.Close()

	reader := mediapipe.NewCtxReader(s.ctx, mediapipe.NewIdentityAnyReader[[]byte](generators.NewIOReader(conn, 1024)))
	writer := mediapipe.NewCtxWriter(s.ctx, mediapipe.NewIdentityAnyWriter[[]byte](consumers.NewIOWriter(conn, 1024)))

	defer reader.Close()
	defer writer.Close()

	s.readers.AddReader(reader)
	s.writers.AddWriter(writer)

	defer s.readers.RemoveReader(reader)
	defer s.writers.RemoveWriter(writer)

	select {
	case <-s.ctx.Done():
	case <-s.pipe.Done():
	case <-reader.Done():
	case <-writer.Done():
	}
}

func (s *Server) Close() error {
	var merr error

	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}

		s.pipe.Close()
		merr = multierr.Append(merr, s.l.Close())
		merr = multierr.Append(merr, s.readers.Close())
		merr = multierr.Append(merr, s.writers.Close())

		// s.wg.Wait()
	})

	return merr
}
