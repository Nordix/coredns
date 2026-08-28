package metrics

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestPrometheusParse(t *testing.T) {
	if err := createTestCertFiles(t); err != nil {
		t.Fatalf("Failed to create test cert files: %v", err)
	}
	defer cleanupTestCertFiles()

	tests := []struct {
		input     string
		shouldErr bool
		addr      string
	}{
		// oks
		{`prometheus`, false, "localhost:9153"},
		{`prometheus localhost:53`, false, "localhost:53"},
		{`prometheus {
			runtime_metrics
		}`, false, "localhost:9153"},
		{`prometheus localhost:53 {
			runtime_metrics
		}`, false, "localhost:53"},
		// tls inline cert/key and client_auth
		{`prometheus localhost:53 {
			tls test_data/server.crt test_data/server.key
		}`, false, "localhost:53"},
		{`prometheus localhost:53 {
			tls test_data/server.crt test_data/server.key
			client_auth NoClientCert
		}`, false, "localhost:53"},
		// fails
		{`prometheus {}`, true, ""},
		{`prometheus {
			runtime_metrics extra_arg
		}`, true, ""},
		{`prometheus /foo`, true, ""},
		{`prometheus a b c`, true, ""},
		{`prometheus localhost:53 {
			client_auth NoClientCert
		}`, true, ""},
		{`prometheus localhost:53 {
			tls test_data/server.crt test_data/server.key
			client_auth Bogus
		}`, true, ""},
	}
	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		m, err := parse(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
			continue
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
			continue
		}

		if test.shouldErr {
			continue
		}

		if test.addr != m.Addr {
			t.Errorf("Test %v: Expected address %s but found: %s", i, test.addr, m.Addr)
		}
	}
}

func TestSetupBasic(t *testing.T) {
	c := caddy.NewTestController("dns", "prometheus localhost:9153")
	if err := setup(c); err != nil {
		t.Fatalf("setup returned error: %v", err)
	}
}
