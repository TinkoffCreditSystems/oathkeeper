package auditlog

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"regexp"
	"sync"
	"testing"

	"github.com/ory/x/logrusx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockProxy struct {
	mock.Mock
	t         *testing.T
	roundTrip func(t *testing.T, r *http.Request) (*http.Response, error)
	director  func(t *testing.T, r *http.Request)
}

func (m *MockProxy) RoundTrip(r *http.Request) (*http.Response, error) {
	m.Called(r)

	return m.roundTrip(m.t, r)
}

func (m *MockProxy) Director(r *http.Request) {
	m.Called(r)
	m.director(m.t, r)
}

type MockSender struct {
	mock.Mock
	mx *sync.Mutex
}

func (m *MockSender) Send(e Event) {
	m.Called(e)

	// Unlock mutex to run tests in parent goroutine.
	m.mx.Unlock()
}

func TestProxyAuditLogDecorator_Director(t *testing.T) {
	request := &http.Request{}
	proxy := &MockProxy{
		director: func(t *testing.T, r *http.Request) {},
	}

	decorator := ProxyAuditLogDecorator{proxy: proxy}

	proxy.On("Director", request).Return()
	decorator.Director(request)
	proxy.AssertExpectations(t)
}

func TestProxyAuditLogDecorator_RoundTrip(t *testing.T) {
	tests := []struct {
		request  *http.Request
		response *http.Response
		hasErr   bool
		proxy    *MockProxy
		builders []EventBuilder
		senders  []Sender
	}{
		{
			request:  nil,
			response: nil,
			hasErr:   true,
			proxy: &MockProxy{
				roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
					return &http.Response{}, nil
				},
			},
			builders: []EventBuilder{},
			senders:  []Sender{},
		},
		{
			request:  &http.Request{},
			response: nil,
			hasErr:   true,
			proxy: &MockProxy{
				roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
					return &http.Response{}, nil
				},
			},
			builders: []EventBuilder{},
			senders:  []Sender{},
		},
		{
			request:  &http.Request{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			response: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			hasErr:   false,
			proxy: &MockProxy{
				roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
					return &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))}, nil
				},
			},
			builders: []EventBuilder{},
			senders:  []Sender{},
		},
		{
			request:  &http.Request{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			response: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			proxy: &MockProxy{
				roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
					return &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))}, nil
				},
			},
			builders: []EventBuilder{},
			senders:  []Sender{},
		},
		{
			request:  &http.Request{Body: ioutil.NopCloser(bytes.NewReader([]byte("")))},
			response: &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))},
			proxy: &MockProxy{
				roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
					return &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))}, nil
				},
			},
			builders: []EventBuilder{},
			senders:  []Sender{},
		},
	}

	for _, tst := range tests {
		decorator := ProxyAuditLogDecorator{proxy: tst.proxy, logger: logrusx.New("Testing Logger", "Test")}

		tst.proxy.On("RoundTrip", tst.request).Return(tst.response, nil)
		resp, err := decorator.RoundTrip(tst.request)

		assert.Equal(t, resp, tst.response)

		if tst.hasErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}

		if tst.response != nil {
			tst.proxy.AssertExpectations(t)
		}

		if tst.response != nil && tst.response.Body != nil {
			err = tst.response.Body.Close()
			assert.Nil(t, err)
		}

		if resp != nil && resp.Body != nil {
			err = resp.Body.Close()
			assert.Nil(t, err)
		}
	}
}

func TestProxyAuditLogDecorator_RoundTrip2(t *testing.T) {
	request, _ := http.NewRequest("GET", "http://localhost:8080/return200", ioutil.NopCloser(bytes.NewReader([]byte(""))))
	response := &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))}
	proxy := &MockProxy{
		roundTrip: func(t *testing.T, r *http.Request) (*http.Response, error) {
			return &http.Response{Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))}, nil
		},
	}
	builders := []EventBuilder{
		{
			URLPattern: "^http://(localhost|127.0.0.1):8080/return200$",
			r:          regexp.MustCompile("^http://(localhost|127.0.0.1):8080/return200$"),
			Method:     "GET",
			Filter: Filter{
				RequestHeaderWhiteList: []string{"User-Agent"},
			},
			DescriptionTemplate: "Curl GET to localhost returned {{meta.response_code}}",
		},
	}

	// Mutex mx to wait for child goroutine to run mock sender.
	var mx sync.Mutex

	sender := &MockSender{mx: &mx}

	decorator := ProxyAuditLogDecorator{
		proxy:    proxy,
		logger:   logrusx.New("", ""),
		builders: builders,
		senders:  []Sender{sender},
	}

	proxy.On("RoundTrip", request).Return(response, nil)
	sender.On("Send", Event{
		Description:    "",
		RequestHeader:  map[string][]string{},
		RequestBody:    map[string]interface{}{},
		ResponseHeader: map[string][]string{},
		ResponseBody:   map[string]interface{}{},
		Meta: map[string]string{
			"method":      "GET",
			"status_code": "0",
			"url":         "http://localhost:8080/return200",
			"user_ip":     "",
		}, OathkeeperError: error(nil),
	}).Return()
	mx.Lock()
	resp, err := decorator.RoundTrip(request)

	mx.Lock()
	defer mx.Unlock()
	assert.Equal(t, resp, response)
	assert.Nil(t, err)
	proxy.AssertExpectations(t)
	sender.AssertExpectations(t)

	if response.Body != nil {
		err = response.Body.Close()
		assert.Nil(t, err)
	}

	if resp.Body != nil {
		err = resp.Body.Close()
		assert.Nil(t, err)
	}
}
