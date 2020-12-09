package auditlog

import (
	"fmt"
)

// Sender is an interface to perform sending events to auditlog.
type Sender interface {
	Send(e Event)
}

// StdoutSender is used when need to write event to standart out.
type StdoutSender struct{}

// Send sends event info to stdout.
func (s *StdoutSender) Send(e Event) {
	fmt.Println(e)
}
