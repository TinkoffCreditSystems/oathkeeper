package auditlog

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/gobuffalo/packr/v2"
	"github.com/ory/gojsonschema"
)

var schemas = packr.New("schemas", "../.schema")

const auditLogConfigSchemaPath = "auditlog.schema.json"

// DeserializeEventBuildersFromFiles validates and deserializes an array of event builders.
func DeserializeEventBuildersFromFiles(configPath string) ([]EventBuilder, error) {
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	schema, err := schemas.Find(auditLogConfigSchemaPath)
	if err != nil {
		return nil, err
	}

	return DeserializeEventBuildersFromBytes(config, schema)
}

// DeserializeEventBuildersFromBytes validates and deserializes an array of event builders.
func DeserializeEventBuildersFromBytes(config, schema []byte) ([]EventBuilder, error) {
	if err := validateJSONConfigSchema(config, schema); err != nil {
		return nil, err
	}

	return deserializeJSONConfig(config)
}

func validateJSONConfigSchema(config, schema []byte) error {
	configLoader := gojsonschema.NewBytesLoader(config)
	schemaLoader := gojsonschema.NewBytesLoader(schema)

	if result, err := gojsonschema.Validate(schemaLoader, configLoader); err != nil {
		return err
	} else if !result.Valid() {
		descriptions := make([]string, 0)
		for _, d := range result.Errors() {
			descriptions = append(descriptions, d.String())
		}

		return errors.New(strings.Join(descriptions, ";"))
	}

	return nil
}

func deserializeJSONConfig(config []byte) ([]EventBuilder, error) {
	var builders []EventBuilder

	if err := json.Unmarshal(config, &builders); err != nil {
		return nil, err
	}

	return builders, nil
}
