package auditlog

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
)

// RequestWithBytesBody combines http.Request with byte slice body that can be read multiple times.
type RequestWithBytesBody struct {
	*http.Request
	Body []byte
}

// ResponseWithBytesBody combines http.Response with byte slice body that can be read multiple times.
type ResponseWithBytesBody struct {
	*http.Response
	Body []byte
}

var errorNilReaderGiven = errors.New("nil reader given")

// NewRequestWithBytesBody copies parent http.Request to the new RequestWithBytesBody.
func NewRequestWithBytesBody(r *http.Request) (*RequestWithBytesBody, error) {
	if r == nil {
		return nil, errors.New("nil request given")
	}

	// Copy parent request body and create new reader.
	raw, newBody, err := teeReader(r.Body)
	if err != nil && !errors.Is(err, errorNilReaderGiven) {
		return nil, err
	}

	r.Body = newBody

	result := RequestWithBytesBody{r.Clone(r.Context()), raw}

	return &result, nil
}

// NewResponseWithBytesBody copies parent http.Response to the new ResponseWithBytesBody.
func NewResponseWithBytesBody(r *http.Response) (*ResponseWithBytesBody, error) {
	if r == nil {
		return nil, errors.New("nil response given")
	}

	// Copy parent response body and create new reader.
	raw, newBody, err := teeReader(r.Body)
	if err != nil {
		return nil, err
	}

	r.Body = newBody

	result := ResponseWithBytesBody{r, raw}

	return &result, nil
}

func teeReader(rc io.ReadCloser) (raw []byte, newReader io.ReadCloser, err error) {
	if rc == nil {
		return nil, nil, errorNilReaderGiven
	}

	raw, err = ioutil.ReadAll(rc)
	if err != nil {
		return nil, nil, err
	}

	newReader = ioutil.NopCloser(bytes.NewReader(raw))

	if err = rc.Close(); err != nil {
		return nil, nil, err
	}

	return raw, newReader, err
}
