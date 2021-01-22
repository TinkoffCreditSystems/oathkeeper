package auditlog

import (
	"errors"
	"io"
	"sync"
)

var errorNilReaderGiven = errors.New("nil reader given")

type ReadCloserWithBuffer struct {
	// rc is a parent ReadCLoser.
	rc io.ReadCloser

	// buffer contains all data read from rc when rc is closed.
	buffer *[]byte
	// m is used to synchronize access to buffer.
	m *sync.RWMutex
}

func NewReadCloserWithBuffer(closer io.ReadCloser) (*ReadCloserWithBuffer, error) {
	if closer == nil {
		return nil, errorNilReaderGiven
	}

	rc := &ReadCloserWithBuffer{
		rc:     closer,
		buffer: &[]byte{},
		m:      new(sync.RWMutex),
	}

	rc.m.Lock()

	return rc, nil
}

// Read reads data from rc and saves it to buffer.
func (r ReadCloserWithBuffer) Read(p []byte) (n int, err error) {
	n, err = r.rc.Read(p)

	if err == nil {
		*r.buffer = append(*r.buffer, p[:n]...)
	}

	return n, err
}

// Close closes rc, makes buffer available and notifies about that.
func (r ReadCloserWithBuffer) Close() error {
	err := r.rc.Close()

	r.m.Unlock()

	return err
}

// GetBufBlocking waits until buffer is ready to read from.
func (r ReadCloserWithBuffer) GetBufBlocking() []byte {
	r.m.RLock()
	defer r.m.RUnlock()

	return *r.buffer
}
