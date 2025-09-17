package utils

import (
	"net"
	"net/http"
	"strings"
)

func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from load balancers/proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (from Nginx/Traefik/etc)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func IsInternalIP(ip string, trusted []string) bool {
	if trusted == nil {
		return true
	}

	for _, network := range trusted {
		if _, ipNet, err := net.ParseCIDR(network); err == nil {
			if ipNet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}

	if isLoopBack(ip) {
		return true
	}

	return false
}

func isLoopBack(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return strings.ToLower(host) == "localhost"
	}

	return ip.IsLoopback()
}
