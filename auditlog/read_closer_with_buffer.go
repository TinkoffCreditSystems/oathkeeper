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
	// mReady is used to synchronize write access to bufferReady.
	mBuffer *sync.Mutex

	// bufferReady is a flag to signal if buffer is ready to be read from.
	bufferReady *bool
	// waiting is an array of goroutines waiting to be notified about buffer is ready.
	waiting *[]chan struct{}
	// m is used to synchronize access to buffer and waiting.
	m *sync.Mutex
}

func NewReadCloserWithBuffer(closer io.ReadCloser) (*ReadCloserWithBuffer, error) {
	if closer == nil {
		return nil, errorNilReaderGiven
	}

	return &ReadCloserWithBuffer{
		rc:      closer,
		buffer:  &[]byte{},
		mBuffer: new(sync.Mutex),
		bufferReady: func() *bool {
			result := false

			return &result
		}(),
		waiting: &[]chan struct{}{},
		m:       new(sync.Mutex),
	}, nil
}

// Read reads data from rc and saves it to buffer.
func (r ReadCloserWithBuffer) Read(p []byte) (n int, err error) {
	r.mBuffer.Lock()
	defer r.mBuffer.Unlock()

	n, err = r.rc.Read(p)

	if err == nil {
		*r.buffer = append(*r.buffer, p[:n]...)
	}

	return n, err
}

// Close closes rc, makes buffer available and notifies about that.
func (r ReadCloserWithBuffer) Close() error {
	err := r.rc.Close()

	r.m.Lock()
	*r.bufferReady = true
	r.m.Unlock()

	for _, c := range *r.waiting {
		c <- struct{}{}
	}

	return err
}

// GetBufBlocking waits until buffer is ready to read from.
func (r ReadCloserWithBuffer) GetBufBlocking() []byte {
	r.m.Lock()

	if !(*r.bufferReady) {
		c := make(chan struct{})
		*r.waiting = append(*r.waiting, c)

		r.m.Unlock()
		<-c
	} else {
		r.m.Unlock()
	}

	return *r.buffer
}
