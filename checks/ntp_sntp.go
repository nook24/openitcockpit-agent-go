package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Simple Network Time Protocol client (RFC 4330) to measure the offset of the local clock.
// It is used on platforms which do not provide the offset of the system time service (e.g. macOS).

const (
	sntpPacketSize = 48
	sntpPort       = "123"

	// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01)
	ntpEpochOffset = 2208988800

	sntpModeClient = 3
	sntpModeServer = 4
	sntpVersion    = 4
	// Leap indicator 3: clock of the server is not synchronized
	sntpLeapAlarm = 3
)

type sntpResult struct {
	Server  string        // Name of the queried server
	Address string        // IP address of the queried server
	Offset  time.Duration // Offset of the local clock, positive if the local clock is behind the server
	Delay   time.Duration // Round trip delay
	Stratum uint8
}

// querySNTP sends a single SNTP request to the server and calculates the offset of the local clock
func querySNTP(ctx context.Context, server string, timeout time.Duration) (*sntpResult, error) {
	return querySNTPAddress(ctx, server, net.JoinHostPort(server, sntpPort), timeout)
}

func querySNTPAddress(ctx context.Context, server, address string, timeout time.Duration) (*sntpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	request := make([]byte, sntpPacketSize)
	request[0] = sntpVersion<<3 | sntpModeClient
	// The transmit timestamp is random and only used to identify the response (RFC 4330 section 5)
	// This avoids leaking the local time and protects against spoofed responses
	if _, err := rand.Read(request[40:48]); err != nil {
		return nil, err
	}

	t1 := time.Now()
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	response := make([]byte, 128)
	var n int
	for {
		n, err = conn.Read(response)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return nil, fmt.Errorf("no response from %s", server)
			}
			return nil, err
		}
		// Ignore responses which do not belong to our request
		if n >= sntpPacketSize && bytes.Equal(response[24:32], request[40:48]) {
			break
		}
	}
	t4 := time.Now()

	return parseSNTPResponse(server, conn.RemoteAddr().String(), response[:n], t1, t4)
}

func isTimeout(err error) bool {
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

// parseSNTPResponse validates the response and calculates offset and delay.
// t1 = local time when the request was sent, t4 = local time when the response was received
func parseSNTPResponse(server, address string, response []byte, t1, t4 time.Time) (*sntpResult, error) {
	if len(response) < sntpPacketSize {
		return nil, fmt.Errorf("invalid response from %s", server)
	}

	leap := response[0] >> 6
	mode := response[0] & 0x7
	stratum := response[1]

	if mode != sntpModeServer {
		return nil, fmt.Errorf("invalid response mode %d from %s", mode, server)
	}
	if stratum == 0 {
		// Kiss-o'-Death packet, the reference id contains the reason (e.g. RATE or DENY)
		return nil, fmt.Errorf("%s denied the request (kiss code %s)", server, strings.TrimRight(string(response[12:16]), "\x00"))
	}
	if leap == sntpLeapAlarm || stratum > 15 {
		return nil, fmt.Errorf("%s is not synchronized", server)
	}

	t2 := ntpTimestampToTime(response[32:40]) // Server receive time
	t3 := ntpTimestampToTime(response[40:48]) // Server transmit time
	if t3.IsZero() {
		return nil, fmt.Errorf("invalid transmit timestamp from %s", server)
	}

	// RFC 4330 section 5
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	delay := t4.Sub(t1) - t3.Sub(t2)
	if delay < 0 {
		delay = 0
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	return &sntpResult{
		Server:  server,
		Address: host,
		Offset:  offset,
		Delay:   delay,
		Stratum: stratum,
	}, nil
}

// ntpTimestampToTime converts a 64 bit NTP timestamp (seconds and fraction since 1900) to time.Time
func ntpTimestampToTime(data []byte) time.Time {
	seconds := binary.BigEndian.Uint32(data[0:4])
	fraction := binary.BigEndian.Uint32(data[4:8])
	if seconds == 0 && fraction == 0 {
		return time.Time{}
	}

	unixSeconds := int64(seconds) - ntpEpochOffset
	// Era 1 starts at 2036-02-07, the most significant bit is 0 from then on (RFC 4330 section 3)
	if seconds&0x80000000 == 0 {
		unixSeconds += 1 << 32
	}
	nanoseconds := (int64(fraction) * 1e9) >> 32
	return time.Unix(unixSeconds, nanoseconds)
}

// timeToNtpTimestamp converts time.Time to a 64 bit NTP timestamp
func timeToNtpTimestamp(t time.Time) []byte {
	data := make([]byte, 8)
	seconds := uint64(t.Unix() + ntpEpochOffset)
	fraction := (uint64(t.Nanosecond()) << 32) / 1e9
	binary.BigEndian.PutUint32(data[0:4], uint32(seconds))
	binary.BigEndian.PutUint32(data[4:8], uint32(fraction))
	return data
}

// parseNtpConfServers returns the servers and pools of a ntp.conf (ntpd), chrony.conf or ntpd.conf (OpenNTPD) file
func parseNtpConfServers(content string) []string {
	var servers []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// "servers" is used by OpenNTPD
		if fields[0] == "server" || fields[0] == "pool" || fields[0] == "servers" {
			// A trailing dot (e.g. time.apple.com.) is a valid fully qualified domain name
			servers = append(servers, fields[1])
		}
	}
	return servers
}
