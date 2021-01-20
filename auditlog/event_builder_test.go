package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"testing"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
	"github.com/stretchr/testify/assert"
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

		{
			[]byte(`{"url_pattern": "http://(127.0.0.1|localhost):8080/api"}`),
			&EventBuilder{
				URLPattern: "http://(127.0.0.1|localhost):8080/api",
				r:          regexp.MustCompile("http://(127.0.0.1|localhost):8080/api"),
			}, nil,
		},

		{
			[]byte(`{"filter": {"request_header": ["User-Agent"], "request_body": ["a", "a.b.c"]}}`),
			&EventBuilder{
				Filter: Filter{
					RequestHeaderWhiteList: []string{"User-Agent"},
					RequestBodyWhiteList:   []string{"a", "a.b.c"},
				},
				r: regexp.MustCompile(""),
			}, nil,
		},
	}

	for _, tst := range tests {
		var result EventBuilder
		err := json.Unmarshal(tst.inp, &result)
		assert.Equal(t, tst.b, &result)
		assert.IsType(t, tst.err, err)
	}
}

func TestEventBuilder_Match(t *testing.T) {
	tests := []struct {
		b          EventBuilder
		url        string
		method     string
		statusCode int
		match      bool
	}{
		{
			b: EventBuilder{
				Method:        "GET",
				r:             regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$"),
				ResponseCodes: []int{http.StatusOK},
			},
			url:        "http://localhost:8080/api",
			method:     "GET",
			statusCode: http.StatusOK,
			match:      true,
		},
		{
			b: EventBuilder{
				Method:        "GET",
				r:             regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$"),
				ResponseCodes: []int{http.StatusOK, http.StatusCreated},
			},
			url:        "http://localhost:8080/api",
			method:     "GET",
			statusCode: http.StatusOK,
			match:      true,
		},
		{
			b: EventBuilder{
				Method:        "GET",
				r:             regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$"),
				ResponseCodes: []int{},
			},
			url:        "http://localhost:8080/api",
			method:     "GET",
			statusCode: http.StatusOK,
			match:      true,
		},
		{
			b: EventBuilder{
				Method:        "GET",
				r:             regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$"),
				ResponseCodes: []int{http.StatusCreated},
			},
			url:        "http://localhost:8080/api",
			method:     "GET",
			statusCode: http.StatusOK,
			match:      false,
		},
		{
			b: EventBuilder{
				Method: "GET",
				r:      regexp.MustCompile("^http://(127.0.0.1|localhost):8080/api$"),
			},
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
		{
			b:      EventBuilder{Method: "GET", r: regexp.MustCompile(`^http://.+/api$`)},
			url:    "http://example.com/api",
			method: "GET",
			match:  true,
		},
	}

	for _, tst := range tests {
		assert.Equal(t, tst.match, tst.b.Match(tst.url, tst.method, tst.statusCode))
	}
}

func TestEventBuilder_Build(t *testing.T) {
	tests := []struct {
		req      *http.Request
		resp     *http.Response
		err      error
		b        EventBuilder
		resEvent Event
	}{
		{
			req:      nil,
			resp:     nil,
			err:      nil,
			b:        EventBuilder{},
			resEvent: NewEvent(),
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", ioutil.NopCloser(bytes.NewReader([]byte(""))))

				return req
			}(),
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader:    make(map[string][]string),
					RequestBody:      make(map[string]interface{}),
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
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
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader:    make(map[string][]string),
					RequestBody:      make(map[string]interface{}),
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					ioutil.NopCloser(bytes.NewReader([]byte(""))),
				)
				req.Header.Add("User-Agent", "curl")
				req.Header.Add("Not-Used", "yes")

				return req
			}(),
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestHeaderWhiteList: []string{"User-Agent"},
				},
			},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader: map[string][]string{
						"User-Agent": {"curl"},
					},
					RequestBody:      make(map[string]interface{}),
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					ioutil.NopCloser(bytes.NewReader([]byte(""))),
				)
				req.Header.Add("key1", "val1")
				req.Header.Add("key1", "val2")
				req.Header.Add("key2", "val3")

				return req
			}(),
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestHeaderWhiteList: []string{"key1", "key2"},
				},
			},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader: map[string][]string{
						"key1": {"val1", "val2"},
						"key2": {"val3"},
					},
					RequestBody:      make(map[string]interface{}),
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					ioutil.NopCloser(bytes.NewReader([]byte(""))),
				)
				req = req.WithContext(context.WithValue(req.Context(), proxy.ContextKeySession,
					&authn.AuthenticationSession{Subject: "user_id_1234"}))

				return req
			}(),
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b:    EventBuilder{},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader:    make(map[string][]string),
					RequestBody:      make(map[string]interface{}),
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"user_id":     "user_id_1234",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
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
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestBodyWhiteList: []string{"a.b.c", "a.b.not_exists", "a.b.c.not_exists", "a.e", "f"},
				},
			},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader: make(map[string][]string),
					RequestBody: map[string]interface{}{
						"a.b.c": "123",
						"a.e":   "abc",
						"f":     "42",
					},
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
		},
		{
			req: func() *http.Request {
				req, _ := http.NewRequest(
					"GET",
					"http://example.com",
					bytes.NewBuffer([]byte(`{"a": {"b": {"c": 123, "d": "d"}, "e": 2.71828 }, "f": [1, 2, 3] }`)),
				)

				return req
			}(),
			resp: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			err:  nil,
			b: EventBuilder{
				Filter: Filter{
					RequestBodyWhiteList: []string{"a.b.c", "a.b.not_exists", "a.b.c.not_exists", "a.e", "f"},
				},
			},
			resEvent: Event{
				Description: "",
				Details: EventDetails{
					RequestHeader: make(map[string][]string),
					RequestBody: map[string]interface{}{
						"a.b.c": 123.,
						"a.e":   2.71828,
						"f":     []interface{}{1., 2., 3.},
					},
					ResponseHeader:   make(map[string][]string),
					ResponseBody:     make(map[string]interface{}),
					FullResponseBody: []byte{},

					Meta: map[string]string{
						"method":      "GET",
						"url":         "http://example.com",
						"user_ip":     "",
						"status_code": "0",
					},

					OathkeeperError: nil,
				},
			},
		},
	}

	for _, tst := range tests {
		req, _ := NewRequestWithBytesBody(tst.req)
		resp, _ := NewResponseWithBytesBody(tst.resp)

		event, err := tst.b.Build(req, resp, tst.err)
		assert.IsType(t, tst.err, err)
		assert.Equal(t, tst.resEvent, *event)
	}
}

func TestDeserializeEventBuildersFromBytes(t *testing.T) {
	tests := []struct {
		config []byte
		schema []byte
		bs     []EventBuilder
		hasErr bool
	}{
		{
			config: nil,
			schema: nil,
			bs:     nil,
			hasErr: true,
		},
		{
			config: nil,
			schema: []byte(``),
			bs:     nil,
			hasErr: true,
		},
		{
			config: nil,
			schema: []byte(`{`),
			bs:     nil,
			hasErr: true,
		},
		{
			config: nil,
			schema: []byte(`{}`),
			bs:     nil,
			hasErr: true,
		},
		{
			config: func() []byte {
				c, err := ioutil.ReadFile("./testdata/correct_config.json")
				if err != nil {
					panic(err)
				}

				return c
			}(),
			schema: func() []byte {
				s, err := schemas.Find(auditLogConfigSchemaPath)
				if err != nil {
					panic(err)
				}

				return s
			}(),
			bs: []EventBuilder{
				{
					URLPattern: "http://(localhost|127.0.0.1):8080/return200",
					r:          regexp.MustCompile("http://(localhost|127.0.0.1):8080/return200"),
					Method:     "GET",
					Filter: Filter{
						RequestHeaderWhiteList: []string{"User-Agent"},
					},
					DescriptionTemplate: "Curl GET to localhost returned {{meta.response_code}}",
				},
				{
					URLPattern: "http://(localhost|127.0.0.1):8080/return200",
					r:          regexp.MustCompile("http://(localhost|127.0.0.1):8080/return200"),
					Method:     "POST",
					Filter: Filter{
						RequestHeaderWhiteList: []string{"User-Agent"},
						RequestBodyWhiteList:   []string{"a.b.c", "d"},
						ResponseBodyWhiteList:  []string{"status"},
					},
					DescriptionTemplate: "Curl POST to localhost returned {{meta.response_code}}",
				},
			},
			hasErr: false,
		},
		{
			config: func() []byte {
				c, err := ioutil.ReadFile("./testdata/wrong_config.json")
				if err != nil {
					panic(err)
				}

				return c
			}(),
			schema: func() []byte {
				s, err := schemas.Find(auditLogConfigSchemaPath)
				if err != nil {
					panic(err)
				}

				return s
			}(),
			bs:     nil,
			hasErr: true,
		},
	}

	for _, tst := range tests {
		if bs, err := DeserializeEventBuildersFromBytes(tst.config, tst.schema); tst.hasErr {
			assert.NotNil(t, err)
			assert.Nil(t, bs)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tst.bs, bs)
		}
	}
}
