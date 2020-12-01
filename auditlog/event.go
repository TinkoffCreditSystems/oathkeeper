package auditlog

import (
	"net/http"
	"net/url"
	"time"
)

// Event is a type for the auditlog event intermediate representation.
type Event struct {
	Method    string
	URL       url.URL
	UserAddr  string
	Timestamp time.Time

	UserID     *string
	StatusCode int

	// Description of the event in human-readable format.
	EventMessage string

	// Environment (dev, stage, prod, etc.)
	Env string
	// Name of program.
	System string
	// Hostname or pod ID.
	Instance string
	// Level (warn, info, etc.)
	Level string

	RequestHeader  map[string]string
	RequestBody    map[string]string
	ResponseHeader map[string]string
	ResponseBody   map[string]string

	OathkeeperError error
}

// EventBuilder is a type to build the Event structure.
type EventBuilder struct{}

// Build method performs filtering of data using rules from config.
func (f *EventBuilder) Build(subj *string, req *http.Request, resp *http.Response, err error) (*Event, error) {
	var e Event

	if req != nil {
		e.Method = req.Method
		e.URL = *req.URL
		e.UserAddr = req.RemoteAddr
		e.Timestamp = time.Now()

		// TODO: filter request header & body
	}

	e.UserID = subj

	if err != nil {
		e.OathkeeperError = err
	}

	if resp != nil {
		e.StatusCode = resp.StatusCode

		// TODO: filter response header & body
	}

	return &e, nil
}
