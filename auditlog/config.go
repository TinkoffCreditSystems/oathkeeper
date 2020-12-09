package auditlog

import (
	log "github.com/sirupsen/logrus"

	"github.com/ory/gojsonschema"
	"github.com/ory/x/logrusx"
)

func ValidateSchema(path string, logger *logrusx.Logger) {
	schemaLoader := gojsonschema.NewReferenceLoader("file:///auditlog.schema.json")
	documentLoader := gojsonschema.NewReferenceLoader(path)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"file":  path,
		}).Fatal("Error while reading Audit Log configuration")
	} else {
		if !result.Valid() {
			for _, desc := range result.Errors() {
				logger.WithFields(log.Fields{
					"error": desc,
					"file":  path,
				}).Error("Error while reading Audit Log configuration")
			}
			logger.WithFields(log.Fields{
				"file": path,
			}).Fatal("Error while reading Audit Log configuration")
		}
	}
}
