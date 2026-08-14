package smtp

// send(ctx) claims "Cancellation of ctx aborts the in-flight connection"
// (smtp.go:88). It does not. The implementation is:
//
//	ch := make(chan result, 1)
//	go func() { ch <- result{err: m.dispatch(addr, to, msg)} }()
//	select {
//	case <-ctx.Done():   return ctx.Err()
//	case r := <-ch:      return r.err
//	}
//
// ctx is never handed to dispatch. On cancellation the CALLER returns and the
// goroutine keeps going, still holding an open TCP connection — and nothing
// downstream carries a deadline either: dispatch → net/smtp.SendMail → net.Dial
// with no timeout, and no SetDeadline anywhere in the file. Against a relay
// that accepts the connection and then says nothing (a blackholed or wedged
// mail server — the exact failure that makes requests get cancelled in the
// first place) the abandoned goroutine parks in bufio.Read on the 220 greeting
// forever. Goroutines and file descriptors then grow 1:1 with aborted sends.
//
// This is not merely untidy: it is the prerequisite for moving mail off the
// request goroutine. Backgrounding the send (so /forgot-password stops being a
// response-time oracle) turns "one parked request" into "one parked goroutine
// per send, retained forever".
//
// The test drives a listener that accepts and never speaks, cancels each send,
// and then asks the two questions that matter: did the goroutines go away, and
// did the sockets close.

import (
	"context"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// silentRelay accepts connections and never writes the SMTP greeting.
type silentRelay struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newSilentRelay(t *testing.T) *silentRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &silentRelay{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns = append(r.conns, c)
			r.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		r.mu.Lock()
		for _, c := range r.conns {
			_ = c.Close()
		}
		r.mu.Unlock()
	})
	return r
}

func (r *silentRelay) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(r.ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func (r *silentRelay) accepted() []net.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]net.Conn, len(r.conns))
	copy(out, r.conns)
	return out
}

// TestSend_CancellationDoesNotOrphanGoroutinesOrSockets is the leak.
func TestSend_CancellationDoesNotOrphanGoroutinesOrSockets(t *testing.T) {
	relay := newSilentRelay(t)
	host, port := relay.hostPort(t)
	m := &Mailer{Host: host, Port: port, From: "noreply@example.com"}

	// Let the runtime settle before taking the baseline.
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	const aborts = 25
	for i := 0; i < aborts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := m.send(ctx, "user@example.com", "s", "b")
		cancel()
		if err == nil {
			t.Fatalf("send %d: expected a cancellation error from a relay that never answers", i)
		}
	}

	// Give a correct implementation time to unwind.
	var got int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		got = runtime.NumGoroutine()
		if got <= baseline+5 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got > baseline+5 {
		t.Errorf("%d goroutines are still running after %d cancelled sends (baseline %d, now %d) — "+
			"each one is parked in net/smtp holding an open socket, and they never come back",
			got-baseline, aborts, baseline, got)
	}

	// The other half of the same leak: the sockets. A cancelled send must
	// close its connection, which the peer sees as EOF.
	conns := relay.accepted()
	if len(conns) == 0 {
		t.Fatalf("the relay accepted no connections — the test never exercised the dial path")
	}
	open := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != io.EOF {
			open++
		}
	}
	if open > 0 {
		t.Errorf("%d of %d connections to the relay are still ESTABLISHED after their sends were cancelled — "+
			"one leaked file descriptor per aborted request", open, len(conns))
	}
}

// POSITIVE CONTROL. Cancellation handling must not turn into "never send":
// a send against a relay that speaks SMTP normally still has to deliver.
func TestSend_AgainstAWorkingRelay_StillDelivers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	received := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		serveMinimalSMTP(c, received)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	m := &Mailer{Host: host, Port: port, From: "noreply@example.com"}

	if err := m.send(context.Background(), "user@example.com", "Hello", "Body"); err != nil {
		t.Fatalf("send against a working relay: %v", err)
	}
	select {
	case body := <-received:
		if !strings.Contains(body, "To: user@example.com") || !strings.Contains(body, "Subject: Hello") {
			t.Fatalf("relay received an unexpected message:\n%s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay never received the message")
	}
}

// serveMinimalSMTP speaks just enough SMTP for net/smtp's SendMail to complete,
// then reports the DATA payload it received.
func serveMinimalSMTP(c net.Conn, out chan<- string) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	write := func(s string) { _, _ = c.Write([]byte(s)) }
	write("220 test ESMTP\r\n")

	buf := make([]byte, 4096)
	var data []byte
	inData := false
	acc := ""
	for {
		n, err := c.Read(buf)
		if n > 0 {
			acc += string(buf[:n])
		}
		if err != nil {
			break
		}
		for {
			idx := strings.Index(acc, "\r\n")
			if idx < 0 {
				break
			}
			line := acc[:idx]
			acc = acc[idx+2:]
			if inData {
				if line == "." {
					inData = false
					write("250 2.0.0 Ok\r\n")
					out <- string(data)
					continue
				}
				data = append(data, []byte(line+"\r\n")...)
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				write("250-test\r\n250 HELP\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				write("250 2.0.0 Ok\r\n")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				write("354 End data with <CR><LF>.<CR><LF>\r\n")
			case strings.HasPrefix(line, "QUIT"):
				write("221 2.0.0 Bye\r\n")
				return
			default:
				write("250 2.0.0 Ok\r\n")
			}
		}
	}
}
