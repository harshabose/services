package main

import (
	"context"
	"time"

	"github.com/harshabose/services/pkg/rtsp"
)

/* EXAMPLE INPUT
ffmpeg -f avfoundation -framerate 30 -i "0" \
  -c:v libx264 \
  -tune zerolatency \
  -preset ultrafast \
  -g 30 \
  -b:v 1000k \
  -f rtsp rtsp://localhost:8554/webcam
*/

/* EXAMPLE OUTPUT
ffplay -fflags nobuffer -flags low_delay \
	-framedrop -avioflags direct
	rtsp://localhost:8554/webcam
*/

func main() {
	ctx := context.Background()

	server := rtsp.NewServer(ctx, nil)
	server.Serve()

	if err := server.WaitForConnection(2 * time.Second); err != nil {
		panic(err)
	}
	<-server.Done()
}
