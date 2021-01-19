package auditlog

// Event is a type for the Audit Log event intermediate representation.
type Event struct {
	// Description of the event in human-readable format.
	Description string

	// Request context parameters.
	RequestHeader    map[string][]string
	RequestBody      map[string]interface{}
	ResponseHeader   map[string][]string
	ResponseBody     map[string]interface{}
	FullResponseBody []byte
	Meta             map[string]string

	OathkeeperError error
}

func NewEvent() Event {
	return Event{
		Description:      "",
		RequestHeader:    make(map[string][]string),
		RequestBody:      make(map[string]interface{}),
		ResponseHeader:   make(map[string][]string),
		ResponseBody:     make(map[string]interface{}),
		FullResponseBody: []byte{},
		Meta:             make(map[string]string),
		OathkeeperError:  nil,
	}
}
