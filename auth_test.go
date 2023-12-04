package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timeodonovan/go-socks5/statute"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	rsp := new(bytes.Buffer)
	srv := NewServer()
	cator := NoAuthAuthenticator{}

	ctx, err := cator.Authenticate(srv, req, rsp, "")
	require.NoError(t, err)
	assert.Equal(t, statute.MethodNoAuth, ctx.Method)
	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodNoAuth}, rsp.Bytes())
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	srv := NewServer()
	cator := UserPassAuthenticator{
		StaticCredentials{
			"foo": "bar",
		},
	}

	ctx, err := cator.Authenticate(srv, req, rsp, "")
	require.NoError(t, err)
	assert.Equal(t, statute.MethodUserPassAuth, ctx.Method)

	val, ok := ctx.Payload["username"]
	require.True(t, ok)
	require.Equal(t, "foo", val)

	val, ok = ctx.Payload["password"]
	require.True(t, ok)
	require.Equal(t, "bar", val)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthSuccess}, rsp.Bytes())
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	rsp := new(bytes.Buffer)
	srv := NewServer()
	cator := UserPassAuthenticator{
		StaticCredentials{
			"foo": "bar",
		},
	}

	ctx, err := cator.Authenticate(srv, req, rsp, "")
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}, rsp.Bytes())
}

func TestHostAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	srv := NewServer()
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")
	cator := UserPassAuthenticator{
		Credentials: PasswordAndHostsCredentials{
			"foo": UserAuth{
				PwHash:   "$2a$10$cWsrCEayMfSoZnLDrPXck.yNSHzcpp7vutsfpDJaf./tPQl2IVYMy",
				Prefixes: []netip.Prefix{prefix},
			},
		},
	}

	ctx, err := cator.Authenticate(srv, req, rsp, "127.0.0.1:47274")
	require.NoError(t, err)
	assert.Equal(t, statute.MethodUserPassAuth, ctx.Method)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthSuccess}, rsp.Bytes())
}

func TestHostAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	srv := NewServer()
	prefix, _ := netip.ParsePrefix("127.0.0.1/32")
	cator := UserPassAuthenticator{
		Credentials: PasswordAndHostsCredentials{
			"foo": UserAuth{
				PwHash:   "$2a$10$cWsrCEayMfSoZnLDrPXck.yNSHzcpp7vutsfpDJaf./tPQl2IVYMy",
				Prefixes: []netip.Prefix{prefix},
			},
		},
	}

	ctx, err := cator.Authenticate(srv, req, rsp, "192.168.0.1:47274")
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}, rsp.Bytes())
}
