package auditlog

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func sleepRandomTime() {
	n, err := rand.Int(rand.Reader, big.NewInt(50))
	if err != nil {
		return
	}

	time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
}

func TestNewReadCloserWithBuffer(t *testing.T) {
	for i := 0; i < 8; i++ {
		testMessage := []byte("test_message")
		closer := ioutil.NopCloser(bytes.NewReader(testMessage))
		closerWithBuffer, err := NewReadCloserWithBuffer(closer)
		assert.Nil(t, err)

		var wg sync.WaitGroup

		for j := 0; j < 1024; j++ {
			wg.Add(1)

			go func() {
				defer wg.Done()

				b := closerWithBuffer.GetBufBlocking()

				assert.Equal(t, b, testMessage)
			}()
		}

		b, err := ioutil.ReadAll(closerWithBuffer)

		assert.Nil(t, err)
		assert.Equal(t, b, testMessage)

		err = closerWithBuffer.Close()

		assert.Nil(t, err)
		wg.Wait()
	}
}

func TestNewReadCloserWithBufferWithRandomSleeps(t *testing.T) {
	for i := 0; i < 8; i++ {
		testMessage := []byte("test_message")
		closer := ioutil.NopCloser(bytes.NewReader(testMessage))
		closerWithBuffer, err := NewReadCloserWithBuffer(closer)

		assert.Nil(t, err)

		var wg sync.WaitGroup

		for i := 0; i < 1024; i++ {
			wg.Add(1)

			go func() {
				defer wg.Done()

				sleepRandomTime()

				b := closerWithBuffer.GetBufBlocking()

				assert.Equal(t, b, testMessage)
			}()
		}

		sleepRandomTime()

		b, err := ioutil.ReadAll(closerWithBuffer)

		assert.Nil(t, err)
		assert.Equal(t, b, testMessage)

		err = closerWithBuffer.Close()

		assert.Nil(t, err)
		wg.Wait()
	}
}
