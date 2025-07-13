package socket

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/harshabose/mediapipe"
	"github.com/harshabose/mediapipe/pkg/duplexers"
)

type Connection struct {
	conn   *websocket.Conn
	reader *mediapipe.AnyReader[[]byte, []byte]
	writer *mediapipe.AnyWriter[[]byte, []byte]
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func NewConnection(ctx context.Context, conn *websocket.Conn, msgType websocket.MessageType, readTimeout time.Duration, writeTimeout time.Duration) *Connection {
	ctx2, cancel := context.WithCancel(ctx)

	rw := duplexers.NewCoderSocket(ctx2, conn, msgType, readTimeout, writeTimeout)

	c := &Connection{
		conn:   conn,
		reader: mediapipe.NewIdentityAnyReader[[]byte](rw),
		writer: mediapipe.NewIdentityAnyWriter[[]byte](rw),
		ctx:    ctx2,
		cancel: cancel,
	}

	return c
}

func (c *Connection) Close() {
	c.once.Do(func() {
		if c.cancel != nil {
			fmt.Println("connection cancel called")
			c.cancel()
		}
	})
}

type Pipe struct {
	readPipe  *mediapipe.FanoutPipe[[]byte, []byte]
	writePipe *mediapipe.MergePipe[[]byte, []byte]
	owner     *Connection
	mux       sync.RWMutex
}

func NewPipe(owner *Connection) *Pipe {
	return &Pipe{
		readPipe:  mediapipe.NewFanoutPipe(owner.ctx, owner.reader),
		writePipe: mediapipe.NewMergePipe(owner.ctx, owner.writer),
		owner:     owner,
	}
}

func (p *Pipe) AddConnection(conn *Connection) {
	defer fmt.Println("fatal error occurred in AddConnection")
	p.readPipe.AddWriter(conn.writer)
	p.writePipe.AddReader(conn.reader)
}
