package socks5

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticCredentials(t *testing.T) {
	srv := NewServer()
	creds := StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	assert.True(t, creds.Valid(srv, "foo", "bar", ""))
	assert.True(t, creds.Valid(srv, "baz", "", ""))
	assert.False(t, creds.Valid(srv, "foo", "", ""))
}

func TestPasswordAndHostsCredentials(t *testing.T) {
	srv := NewServer()
	creds := PasswordAndHostsCredentials{
		"foo": UserAuth{
			PwHash: "$2a$10$cWsrCEayMfSoZnLDrPXck.yNSHzcpp7vutsfpDJaf./tPQl2IVYMy",
			Hosts:  []string{"127.0.0.1"},
		},
		"baz": UserAuth{
			PwHash: "$2a$10$cWsrCEayMfSoZnLDrPXck.yNSHzcpp7vutsfpDJaf./tPQl2IVYMy",
			Hosts:  []string{"127.0.0.1"},
		},
	}

	assert.True(t, creds.Valid(srv, "foo", "bar", "127.0.0.1:47274"))
	assert.False(t, creds.Valid(srv, "baz", "bar", "192.168.0.1:47274"))
}
