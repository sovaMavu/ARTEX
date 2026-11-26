package db

import (
	"regexp"
	"testing"
)

// The built-in "delete-like endpoint path" rule matches the entire tool_input JSON
// string, so the cases are given directly in JSON form, consistent with the subject
// the Interceptor actually receives.
func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET hitting a delete endpoint
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST hitting a delete endpoint
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // v1's path rule forbids a suffix; covered here
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("should have hit but was allowed: %s", s)
		}
	}

	// The verb must be followed by a separator, so read-only paths like /delivery and
	// /details are not falsely intercepted.
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // the delete verb appears in the domain, not the path
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("false interception: %s", s)
		}
	}
}

// The runner approval gates match the serialized MCP tool arguments. They must
// survive whitespace/newlines added by the JSON marshaler and must not fire on
// the false/other-profile cases.
func TestKaliRunnerInterceptPatterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		hit     []string
		miss    []string
	}{
		{
			name:    "full_tcp",
			pattern: runnerFullTCPPattern,
			hit: []string{
				`{"profile":"full_tcp","target":"10.0.0.1"}`,
				"{\n  \"profile\" : \"full_tcp\"\n}",
			},
			miss: []string{
				`{"profile":"top1000"}`,
				`{"profile":"custom","ports":"1-1024"}`,
			},
		},
		{
			name:    "syn",
			pattern: runnerSYNPattern,
			hit:     []string{`{"syn":true}`, "{\"syn\" :\ttrue}"},
			miss:    []string{`{"syn":false}`, `{"os_detect":true}`},
		},
		{
			name:    "os_detect",
			pattern: runnerOSDetectPattern,
			hit:     []string{`{"os_detect":true}`},
			miss:    []string{`{"os_detect":false}`, `{"syn":true}`},
		},
		{
			name:    "axfr",
			pattern: runnerAXFRPattern,
			hit:     []string{`{"axfr":true,"target":"example.com"}`},
			miss:    []string{`{"axfr":false}`, `{"record_types":["AXFR"]}`},
		},
	}
	for _, c := range cases {
		re := regexp.MustCompile(c.pattern)
		for _, s := range c.hit {
			if !re.MatchString(s) {
				t.Errorf("%s: should have hit: %s", c.name, s)
			}
		}
		for _, s := range c.miss {
			if re.MatchString(s) {
				t.Errorf("%s: false interception: %s", c.name, s)
			}
		}
	}
}
