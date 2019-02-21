package dnsserver

import (
	"testing"
	"time"
)

func Test_StartStop(t *testing.T) {
	srv, err := NewServer(&Config{
		ipv4Addr:   "192.168.1.33",
		port:       53,
		DoH:        true,
		serverlist: []string{"1.1.1.1:53"},
		cache:      "ARC",
	})
	if err != nil {
		t.Fatal("failed to new server,", err)
	}
	srv.Run()
	time.Sleep(29 * time.Second)
	srv.ShutDown()
}
