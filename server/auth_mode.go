package server

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// authMode decides how requireAuth behaves. The default (ARTEX_REQUIRE_AUTH unset)
// is "open": start-up login is off, matching the single-operator loopback
// deployment. Setting ARTEX_REQUIRE_AUTH=1 restores the previous password login
// exactly, with no code change and no rebuild.
//
// "Open" is scoped twice on purpose. Without a JWT nothing identifies the caller,
// so the API — which can register custom shell tools and write files — must not be
// reachable from anywhere but the operator's own machine: circle bounds which peers
// may use the open path, and sameOrigin stops a page on another site driving the
// API in the operator's browser.
type authMode struct {
	require bool
	circle  []*net.IPNet
}

// authModeFromEnv reads ARTEX_REQUIRE_AUTH and ARTEX_NOAUTH_CIDRS.
func authModeFromEnv() authMode {
	m := authMode{require: envBool("ARTEX_REQUIRE_AUTH")}
	for _, raw := range strings.Split(os.Getenv("ARTEX_NOAUTH_CIDRS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if n := parsePeerNetwork(raw); n != nil {
			m.circle = append(m.circle, n)
		} else {
			log.Printf("[auth] ignoring malformed ARTEX_NOAUTH_CIDRS entry %q (want a CIDR, or a bare IP meaning that one host)", raw)
		}
	}
	if len(m.circle) == 0 {
		m.circle = defaultNoAuthCIDRs()
	}
	return m
}

// parsePeerNetwork accepts a CIDR, or a bare IP understood as a single host
// (/32, /128). Accepting the bare form matters: an operator writing
// "ARTEX_NOAUTH_CIDRS=10.0.0.5" and having it silently ignored — falling back to
// loopback — is exactly the kind of quiet failure a security control cannot have.
func parsePeerNetwork(raw string) *net.IPNet {
	if _, n, err := net.ParseCIDR(raw); err == nil {
		return n
	}
	if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	return nil
}

// defaultNoAuthCIDRs is the loopback set: the UI, the traffic proxy and any CLI
// client on the same machine. A container's peer is the host's docker bridge
// address, which is covered by ARTEX_NOAUTH_CIDRS when it needs to be.
func defaultNoAuthCIDRs() []*net.IPNet {
	var out []*net.IPNet
	for _, raw := range []string{"127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(raw); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// envBool reports whether the named env var is set to a truthy value.
func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// allowsPeer reports whether remoteAddr (host:port) is inside the no-auth circle.
func (m authMode) allowsPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	// Tolerate a bare IP or an IPv6 literal without brackets.
	host = strings.Trim(host, "[]")
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 { // fe80::1%eth0
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range m.circle {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sameOrigin rejects cross-site writes in no-auth mode. With no token there is no
// cookie or bearer header to separate a first-party POST from a fetch() issued by
// a page on another origin. A missing Origin is allowed on purpose: non-browser
// clients (curl, scripts, health probes) are the operator.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if origin == "null" { // sandboxed iframe / file://; never the console
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// openFor reports whether an unauthenticated request from this peer is allowed.
//
// The topology matters: with docker-compose the container is published on the
// HOST's loopback port, but inside the container the peer is Docker's userland
// proxy (docker-proxy, or a desktop host-gateway address) — never 127.0.0.1. A
// strict loopback check therefore locks the operator out of their own UI. To close
// that gap without trusting arbitrary peers:
//
//   - the configured circle applies to public peers;
//   - private-range peers are accepted only when the request's Host names this
//     machine (localhost / loopback / a bare host name) — Docker's published port
//     forwards the original Host header, so a remote browser reaching a LAN-published
//     port arrives with its own host name and is refused, while the operator's
//     loopback browser is let through;
//   - everything public or unknown is refused.
//
// Publish on 127.0.0.1 (the default) and the peer is a harmless bridge address.
// Publish on 0.0.0.0 and this Host check is what keeps the internet out.
func (s *Server) openFor(r *http.Request) bool {
	if s.auth.require {
		return false
	}
	if s.auth.allowsPeer(r.RemoteAddr) {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return isPrivatePeer(host) && loopbackHost(r.Host)
}

// isPrivatePeer reports whether addr is an RFC1918 / IPv6 ULA / link-local /
// loopback peer: an infrastructure address (Docker bridge, host-gateway, LAN host),
// never a routed-internet client.
func isPrivatePeer(addr string) bool {
	addr = strings.Trim(strings.TrimSpace(addr), "[]")
	if zone := strings.LastIndexByte(addr, '%'); zone >= 0 {
		addr = addr[:zone]
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// loopbackHost reports whether the request's Host names this machine: a loopback
// address, "localhost", or a bare single-label host name. Any dotted name or
// non-loopback IP literal is refused — that is a remote browser's own Host header.
func loopbackHost(hostport string) bool {
	if hostport == "" {
		return false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(strings.TrimSuffix(strings.Trim(host, "[]"), "."), "[]"))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host != "" && !strings.Contains(host, ".")
}

// authKeyDir resolves the directory holding jwt.key. It is only created when a
// write actually happens (readOnly prevents it), so the open path never touches
// the filesystem beyond a stat.
func authKeyDir(explicit string) string {
	if dir := strings.TrimSpace(explicit); dir != "" {
		return dir
	}
	return filepath.Join(os.TempDir(), "artex-keys")
}
