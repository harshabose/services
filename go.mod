module github.com/harshabose/services

go 1.24.1

require (
	github.com/bluenviron/gortsplib/v4 v4.15.0
	github.com/coder/websocket v1.8.13
	github.com/harshabose/mediapipe v0.0.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/pion/rtp v1.8.20
	golang.org/x/time v0.12.0
)

require (
	github.com/asticode/go-astiav v0.37.0 // indirect
	github.com/asticode/go-astikit v0.42.0 // indirect
	github.com/bluenviron/mediacommon/v2 v2.3.0 // indirect
	github.com/emirpasic/gods/v2 v2.0.0-alpha // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/harshabose/tools v0.0.0 // indirect
	github.com/pion/logging v0.2.3 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.15 // indirect
	github.com/pion/sdp/v3 v3.0.14 // indirect
	github.com/pion/srtp/v3 v3.0.6 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace (
	github.com/harshabose/tools => ../tools
	github.com/harshabose/mediapipe => ../mediapipe
)
