package auditlog

import (
	"strconv"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
)

// Event is a type for the Audit Log event intermediate representation.
type Event struct {
	// Class of the changed object
	Class string `json:"class"`
	// Description of the event in human-readable format.
	Description string `json:"description"`

	// Request context parameters.
	Details EventDetails `json:"details"`
}

type EventDetails struct {
	RequestHeader    map[string][]string    `json:"request_header"`
	RequestBody      map[string]interface{} `json:"request_body"`
	ResponseHeader   map[string][]string    `json:"response_header"`
	ResponseBody     map[string]interface{} `json:"response_body"`
	FullResponseBody interface{}            `json:"full_response_body"`
	Meta             map[string]string      `json:"meta"`
}

func NewEvent() Event {
	return Event{
		Class:       "",
		Description: "",
		Details: EventDetails{
			RequestHeader:    make(map[string][]string),
			RequestBody:      make(map[string]interface{}),
			ResponseHeader:   make(map[string][]string),
			ResponseBody:     make(map[string]interface{}),
			FullResponseBody: struct{}{},
			Meta:             make(map[string]string),
		},
	}
}

// SetRequestMeta is a setter for Request meta information.
func (d *EventDetails) SetRequestMeta(r *RequestWithBytesBody) {
	d.Meta["method"] = r.Method
	d.Meta["url"] = r.URL.String()
	d.Meta["user_ip"] = r.RemoteAddr

	if sess, ok := r.Context().Value(proxy.ContextKeySession).(*authn.AuthenticationSession); ok {
		d.Meta["user_id"] = sess.Subject
	}
}

// SetRequestMeta is a setter for Response meta information.
func (d *EventDetails) SetResponseMeta(r *ResponseWithBytesBody) {
	d.Meta["status_code"] = strconv.Itoa(r.StatusCode)
}
