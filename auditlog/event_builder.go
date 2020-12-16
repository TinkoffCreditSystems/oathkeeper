package auditlog

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ory/x/logrusx"
	log "github.com/sirupsen/logrus"

	"github.com/ory/gojsonschema"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/proxy"
)

// EventBuilder is a type to build the Event structure.
type EventBuilder struct {
	URLPattern string `json:"url_pattern"`
	Method     string `json:"http_method"`
	Filter     Filter `json:"filter"`
	// Logger string `json:"logger"`
	DescriptionTemplate string `json:"description_template"`

	r *regexp.Regexp
}

type Filter struct {
	RequestHeaderWhiteList  []string `json:"request_header"`
	RequestBodyWhiteList    []string `json:"request_body"`
	ResponseHeaderWhiteList []string `json:"response_header"`
	ResponseBodyWhiteList   []string `json:"response_body"`
}

// UnmarshalJSON implements the Unmarshaler interface for the EventBuilder struct.
func (b *EventBuilder) UnmarshalJSON(raw []byte) error {
	var err error

	// An additional struct like in rule.go.
	var bb struct {
		URLPattern          string `json:"url_pattern"`
		Method              string `json:"http_method"`
		Filter              Filter `json:"filter"`
		DescriptionTemplate string `json:"description_template"`
		r                   *regexp.Regexp
	}

	if err = json.Unmarshal(raw, &bb); err != nil {
		return err
	}

	*b = bb
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

		e.RequestHeader = filterHeader(req.Header, b.Filter.RequestHeaderWhiteList)
		filterBody(&req.Body, b.Filter.RequestBodyWhiteList)
		// TODO: filter request body.
	}

	if err != nil {
		e.OathkeeperError = err
	}

	if resp != nil {
		e.Meta["status_code"] = strconv.Itoa(resp.StatusCode)

		e.ResponseHeader = filterHeader(resp.Header, b.Filter.RequestHeaderWhiteList)
		filterBody(&resp.Body, b.Filter.RequestBodyWhiteList)
		// TODO: filter response body.
	}

	// TODO generate Description.

	return &e, nil
}

func filterBody(b *io.ReadCloser, wl []string) map[string]interface{} {
	result := make(map[string]interface{})

	return result
}

// filterHeader filters HTTP header according to the white list.
func filterHeader(h http.Header, wl []string) map[string]string {
	result := make(map[string]string)
	for _, key := range wl {
		result[key] = h.Get(key)
	}
	return result
}

// DeserializeEventBuilders validates and deserializes an array of event builders using file with path "path".
func DeserializeEventBuilders(path string, logger *logrusx.Logger) []EventBuilder {
	validateJSONConfigSchema(path, logger)
	return deserializeJSONConfig(path, logger)
}

// validateJSONConfigSchema checks if config file fits JSON schema.
func validateJSONConfigSchema(path string, logger *logrusx.Logger) {
	schemaLoader := gojsonschema.NewReferenceLoader("file:///auditlog.schema.json")
	documentLoader := gojsonschema.NewReferenceLoader(path)

	if result, err := gojsonschema.Validate(schemaLoader, documentLoader); err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"file":  schemaLoader.JsonSource(),
		}).Fatal("Error while validating Audit Log configuration")
	} else {
		if !result.Valid() {
			for _, desc := range result.Errors() {
				logger.WithFields(log.Fields{
					"error": desc,
					"file":  documentLoader.JsonSource(),
				}).Error("Error while validating Audit Log configuration")
			}
			logger.WithFields(log.Fields{
				"file": documentLoader.JsonSource(),
			}).Fatal("Error while validating Audit Log configuration")
		}
	}
}

// deserializeJSONConfig takes the path of file which was checked to fit JSON schema
// and deserializes it to the array of EventBuilder
func deserializeJSONConfig(path string, logger *logrusx.Logger) []EventBuilder {
	// An alternative way to deserialize data is to use documentLoader.LoadJSON.
	// That way is more secure because of deserializing assuredly the same data which
	// was validated through schema and be no afraid if file was changed.
	// But that way requires a lot of manual work with JSON unmarshalling using interface{}.
	// We'll just use Go default JSON Unmarshall.

	if !strings.HasPrefix(path, "file://") {
		logger.WithFields(log.Fields{
			"file": path,
		}).Fatal("Only reading from file:// is implemented")
	}

	p := strings.TrimPrefix(path, "file://")

	f, err := ioutil.ReadFile(p)
	if err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"file":  path,
		}).Fatal("Error while validating Audit Log configuration")
	}

	var builders []EventBuilder

	if err = json.Unmarshal(f, &builders); err != nil {
		logger.WithFields(log.Fields{
			"error": err,
			"file":  path,
		}).Fatal("Error while validating Audit Log configuration")
	}

	return builders
}
