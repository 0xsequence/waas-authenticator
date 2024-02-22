package telemetry

import (
	"bytes"
	"net"
	"net/http"
	"strings"
)

// getIPAddress gets the real ip address from headers
// if not found it returns r.RemoteAddr
func getIPAddress(r *http.Request) string {
	ipHeaders := []string{
		"True-Client-IP",
		"X-Forwarded-For",
		"X-Real-Ip",
	}
	for _, h := range ipHeaders {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left
		for i := len(addresses) - 1; i >= 0; i-- {
			// header can contain spaces too, strip those out.
			ip := strings.TrimSpace(addresses[i])
			if ip == "" {
				continue
			}
			return ip
		}
	}
	return ipRemoteAddr(r.RemoteAddr)
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	// TODO: implement ipv6 ranges
	return false
}

func ipRemoteAddr(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

// ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

// refer https://datatracker.ietf.org/doc/html/rfc1918#section-3
var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}
