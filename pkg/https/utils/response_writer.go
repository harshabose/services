package utils

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

type ResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
}

func NewResponseWriter(w http.ResponseWriter, code int) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		statusCode:     code,
		headerWritten:  false,
	}
}

func (rw *ResponseWriter) WriteHeader(code int) {
	if rw.headerWritten {
		return
	}
	rw.headerWritten = true
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}

func (rw *ResponseWriter) Write(data []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(200)
	}
	return rw.ResponseWriter.Write(data)
}

func (rw *ResponseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (rw *ResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rw.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return errors.New("push not supported")
}

func (rw *ResponseWriter) StatusCode() int {
	return rw.statusCode
}
