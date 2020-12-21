package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
)

func TestEventBuilder_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		inp []byte
		b   *EventBuilder
		err error
	}{
		{[]byte(``), &EventBuilder{}, &json.SyntaxError{}},
		{[]byte(`}`), &EventBuilder{}, &json.SyntaxError{}},
		{[]byte(`{}}`), &EventBuilder{}, &json.SyntaxError{}},

		{[]byte(`{}`), &EventBuilder{r: regexp.MustCompile("")}, nil},
		{[]byte(`{"not_exists": "ok"}`), &EventBuilder{r: regexp.MustCompile("")}, nil},

		{[]byte(`{"url_pattern": "http://(127.0.0.1|localhost):8080/api"}`),
			&EventBuilder{URLPattern: "http://(127.0.0.1|localhost):8080/api",
				r: regexp.MustCompile("http://(127.0.0.1|localhost):8080/api")}, nil},

		{[]byte(`{"filter": {"request_header": ["User-Agent"], "request_body": ["a", "a.b.c"]}}`),
			&EventBuilder{
				Filter: Filter{
					RequestHeaderWhiteList: []string{"User-Agent"},
					RequestBodyWhiteList:   []string{"a", "a.b.c"},
				},
				r: regexp.MustCompile(""),
			}, nil},
	}

	for _, test := range tests {
		var result EventBuilder
		err := json.Unmarshal(test.inp, &result)
		assert.Equal(t, test.b, &result)
		assert.IsType(t, test.err, err)
	}
}

func TestEventBuilder_Match(t *testing.T) {
	tests := []struct {
		b      EventBuilder
		url    string
		method string
		match  bool
	}{
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$")},
			url:    "http://localhost:8080/api",
			method: "GET",
			match:  true,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api")},
			url:    "http://localhost:8080/api/tail",
			method: "GET",
			match:  true,
		},
		{
			b:      EventBuilder{Method: "PUT", r: regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api")},
			url:    "http://localhost:8080/api",
			method: "GET",
			match:  false,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile("^ftp://(127.0.0.1|localhost):8080/api")},
			url:    "http://localhost:8080/api",
			method: "GET",
			match:  false,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile(`^http://(127.0.0.1|localhost):8080/api/\d+$`)},
			url:    "http://localhost:8080/api/1234",
			method: "GET",
			match:  true,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile(`^http://(127.0.0.1|localhost):8080/api/\d+$`)},
			url:    "http://localhost:8080/api/1234abc",
			method: "GET",
			match:  false,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile(`^http://(127.0.0.1|localhost):8080/api/d+$`)},
			url:    "http://localhost:8080/api/",
			method: "GET",
			match:  false,
		},
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile(`^http://(127.0.0.1|localhost):8080/api`)},
			url:    "http://example.com/api",
			method: "GET",
			match:  false,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.match, test.b.Match(test.url, test.method))
	}
}

func TestEventBuilder_Build(t *testing.T) {
	tests := []struct {
		req      *http.Request
		resp     *http.Response
		err      error
		b        EventBuilder
		resEvent Event
		resErr   error
	}{
		{
			req:      nil,
			resp:     nil,
			err:      nil,
			b:        EventBuilder{},
			resEvent: NewEvent(),
			resErr:   nil,
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				return req
			}(),
			resp: nil,
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description:    "",
				RequestHeader:  make(map[string]string),
				RequestBody:    make(map[string]interface{}),
				ResponseHeader: make(map[string]string),
				ResponseBody:   make(map[string]interface{}),

				Meta: map[string]string{
					"method":  "GET",
					"url":     "http://example.com",
					"user_ip": "",
				},

				OathkeeperError: nil,
			},
			resErr: nil,
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					bytes.NewBuffer([]byte(`{`)),
				)
				return req
			}(),
			resp: nil,
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description:    "",
				RequestHeader:  make(map[string]string),
				RequestBody:    make(map[string]interface{}),
				ResponseHeader: make(map[string]string),
				ResponseBody:   make(map[string]interface{}),

				Meta: map[string]string{
					"method":  "GET",
					"url":     "http://example.com",
					"user_ip": "",
				},

				OathkeeperError: nil,
			},
			resErr: nil,
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					nil,
				)
				req.Header.Add("User-Agent", "curl")
				req.Header.Add("Not-Used", "yes")
				return req
			}(),
			resp: nil,
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestHeaderWhiteList: []string{"User-Agent"},
				},
			},
			resEvent: Event{
				Description: "",
				RequestHeader: map[string]string{
					"User-Agent": "curl",
				},
				RequestBody:    make(map[string]interface{}),
				ResponseHeader: make(map[string]string),
				ResponseBody:   make(map[string]interface{}),

				Meta: map[string]string{
					"method":  "GET",
					"url":     "http://example.com",
					"user_ip": "",
				},

				OathkeeperError: nil,
			},
			resErr: nil,
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					nil,
				)
				req = req.WithContext(context.WithValue(req.Context(), proxy.ContextKeySession,
					&authn.AuthenticationSession{Subject: "user_id_1234"}))
				return req
			}(),
			resp: nil,
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description:    "",
				RequestHeader:  make(map[string]string),
				RequestBody:    make(map[string]interface{}),
				ResponseHeader: make(map[string]string),
				ResponseBody:   make(map[string]interface{}),

				Meta: map[string]string{
					"method":  "GET",
					"url":     "http://example.com",
					"user_ip": "",
					"user_id": "user_id_1234",
				},

				OathkeeperError: nil,
			},
			resErr: nil,
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					bytes.NewBuffer([]byte(`{"a": {"b": {"c": "123", "d": "qwe"}, "e": "abc"}, "f": "42"}`)),
				)
				return req
			}(),
			resp: nil,
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestBodyWhiteList: []string{"a.b.c", "a.b.not_exists", "a.b.c.not_exists", "a.e", "f"},
				},
			},
			resEvent: Event{
				Description:   "",
				RequestHeader: make(map[string]string),
				RequestBody: map[string]interface{}{
					"a.b.c": "123",
					"a.e":   "abc",
					"f":     "42",
				},
				ResponseHeader: make(map[string]string),
				ResponseBody:   make(map[string]interface{}),

				Meta: map[string]string{
					"method":  "GET",
					"url":     "http://example.com",
					"user_ip": "",
				},

				OathkeeperError: nil,
			},
			resErr: nil,
		},
	}

	for _, test := range tests {
		event, err := test.b.Build(test.req, test.resp, test.err)
		assert.Equal(t, test.resEvent, *event)
		assert.IsType(t, test.err, err)
	}
}
