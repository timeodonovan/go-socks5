package socks5

import (
	"golang.org/x/crypto/bcrypt"
	"net/netip"
	"strings"
)

// CredentialStore is used to support user/pass authentication optional network addr
// if you want to limit user network addr,you can refuse it.
type CredentialStore interface {
	Valid(sf *Server, user, password, userAddr string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

// Valid implement interface CredentialStore
func (s StaticCredentials) Valid(sf *Server, user, password, _ string) bool {
	pass, ok := s[user]
	return ok && password == pass
}

// UserAuth holds a mapped user's bcrypt password hash and allowed hosts list
type UserAuth struct {
	PwHash   string
	Prefixes []netip.Prefix
}

// PasswordAndHostsCredentials credential store for users with password hash and allowed hosts list
type PasswordAndHostsCredentials map[string]UserAuth

// Valid implement interface CredentialStore
func (s PasswordAndHostsCredentials) Valid(sf *Server, user, password, hostPort string) bool {
	// Lookup the username
	userPassHost, ok := s[user]
	if !ok {
		sf.logger.Errorf("credentials: no entry for username '%s' in credential store", user)
		return false
	}

	// Check the password
	err := bcrypt.CompareHashAndPassword([]byte(userPassHost.PwHash), []byte(password))
	if err != nil {
		sf.logger.Errorf("credentials: password mismatch for username %s", user)
		return false
	}

	// Finally check if the host is allowed
	ip := strings.SplitN(hostPort, ":", 2)[0]

	if !ipInPrefixList(userPassHost.Prefixes, ip) {
		sf.logger.Errorf("credentials: host %s is not defined in %s's allowed host list", ip, user)
		return false
	}

	return true
}

// ipInPrefixList
func ipInPrefixList(prefixes []netip.Prefix, ip string) bool {
	var exists = false

	// Attempt to parse the IP string into an addr
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	// Check if the addr exists in any of the allowed prefixes
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			exists = true
			break
		}
	}

	return exists
}
