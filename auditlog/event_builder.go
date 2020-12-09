package auditlog

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
)

// EventBuilder is a type to build the Event structure.
type EventBuilder struct {
	URLPattern string `json:"url_pattern"`

	Method string `json:"http_method"`

	RequestHeaderWhiteList  []string `json:"filter.request_header"`
	RequestBodyWhiteList    []string `json:"filter.request_body"`
	ResponseHeaderWhiteList []string `json:"filter.response_header"`
	ResponseBodyWhiteList   []string `json:"filter.response_body"`

	// Logger string `json:"logger"`

	DescriptionTemplate string `json:"description_template"`

	r *regexp.Regexp
}

// UnmarshalJSON implements the Unmarshaller interface for the EventBuilder struct.
func (b *EventBuilder) UnmarshalJSON(raw []byte) error {
	err := json.Unmarshal(raw, b)

	if err != nil {
		return err
	}

	b.r, err = regexp.Compile(b.URLPattern)

	return err
}

// Match method verifies if this builder must be applied to request with given url and method.
func (b *EventBuilder) Match(url, method string) bool {
	if b.Method != method {
		return false
	}

	if !b.r.MatchString(url) {
		return false
	}

	return true
}

// Build method performs filtering of data using rules from config.
func (b *EventBuilder) Build(req *http.Request, resp *http.Response, err error) (*Event, error) {
	e := NewEvent()

	if req != nil {
		e.Meta["method"] = req.Method
		e.Meta["url"] = req.URL.String()
		e.Meta["user_ip"] = req.RemoteAddr
		e.Timestamp = time.Now()

		if sess, ok := req.Context().Value(proxy.ContextKeySession).(*authn.AuthenticationSession); ok {
			e.Meta["user_id"] = sess.Subject
		}

		// TODO: filter request header & body.
	}

	if err != nil {
		e.OathkeeperError = err
	}

	if resp != nil {
		e.Meta["status_code"] = strconv.Itoa(resp.StatusCode)

		// TODO: filter response header & body.
	}

	// TODO generate Description.

	return &e, nil
}
