package auditlog

import (
	log "github.com/sirupsen/logrus"

	"github.com/ory/x/logrusx"
)

// Sender is an interface to perform sending events to auditlog.
type Sender interface {
	Send(e Event, l *logrusx.Logger)
}

// StdoutSender is used when need to write event to standard out.
type StdoutSender struct{}

// Send sends event info to stdout.
func (s *StdoutSender) Send(e Event, l *logrusx.Logger) {
	l.WithFields(log.Fields{
		"service_name": "kek",
		"event":        e,
	}).Info("AuditLog Message")
}
