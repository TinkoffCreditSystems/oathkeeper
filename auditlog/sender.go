package auditlog

import (
	"github.com/ory/x/logrusx"
	log "github.com/sirupsen/logrus"
)

// Sender is an interface to perform sending events to auditlog.
type Sender interface {
	Send(e Event)
}

// StdoutSender is used when need to write event to standard out.
type StdoutSender struct {
	l *logrusx.Logger
}

// Send sends event info to stdout.
func (s *StdoutSender) Send(e Event) {
	s.l.WithFields(log.Fields{
		"service_name": "Audit Log",
		"event":        e,
	}).Info("AuditLog Message")
}

// KafkaSender is used when need to save event to kafka.
type KafkaSender struct{}

// Send sends event info to kafka.
func (s *KafkaSender) Send(e Event) {
	// TODO(torilov) implement kafka sender.
}
