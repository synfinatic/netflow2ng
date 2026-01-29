package collector

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRingBuffer_PushPop(t *testing.T) {
	rb := NewRingBuffer(8)

	// Push some items
	for i := 0; i < 5; i++ {
		work := PacketWork{
			Data:   []byte{byte(i)},
			Length: 1,
		}
		if !rb.Push(work) {
			t.Errorf("Push failed at index %d", i)
		}
	}

	if rb.Len() != 5 {
		t.Errorf("Expected length 5, got %d", rb.Len())
	}

	// Pop items
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		work, ok := rb.Pop(ctx)
		if !ok {
			t.Errorf("Pop failed at index %d", i)
		}
		if work.Data[0] != byte(i) {
			t.Errorf("Expected data %d, got %d", i, work.Data[0])
		}
	}

	if rb.Len() != 0 {
		t.Errorf("Expected length 0, got %d", rb.Len())
	}
}

func TestRingBuffer_Full(t *testing.T) {
	rb := NewRingBuffer(4) // Will round to power of 2

	// Fill the buffer
	for i := 0; i < 4; i++ {
		work := PacketWork{Data: []byte{byte(i)}, Length: 1}
		if !rb.Push(work) {
			t.Errorf("Push should succeed at index %d", i)
		}
	}

	// Buffer should be full
	work := PacketWork{Data: []byte{99}, Length: 1}
	if rb.Push(work) {
		t.Error("Push should fail when buffer is full")
	}
}

func TestRingBuffer_Close(t *testing.T) {
	rb := NewRingBuffer(8)

	// Push an item
	rb.Push(PacketWork{Data: []byte{1}, Length: 1})

	// Close the buffer
	rb.Close()

	// Pop should still return the existing item
	ctx := context.Background()
	_, ok := rb.Pop(ctx)
	if !ok {
		t.Error("Should be able to pop existing items after close")
	}

	// Push should fail after close
	if rb.Push(PacketWork{Data: []byte{2}, Length: 1}) {
		t.Error("Push should fail after close")
	}
}

func TestRingBuffer_Concurrent(t *testing.T) {
	rb := NewRingBuffer(1024)
	ctx := context.Background()

	var pushed, popped atomic.Int64
	var wg sync.WaitGroup

	// Start producers
	numProducers := 4
	numItems := 1000
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numItems; j++ {
				work := PacketWork{Data: []byte{1}, Length: 1}
				if rb.PushBlocking(ctx, work) {
					pushed.Add(1)
				}
			}
		}()
	}

	// Start consumers
	numConsumers := 4
	done := make(chan bool)
	for i := 0; i < numConsumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					// Drain remaining items
					for {
						_, ok := rb.Pop(ctx)
						if !ok {
							return
						}
						popped.Add(1)
					}
				default:
					_, ok := rb.Pop(ctx)
					if ok {
						popped.Add(1)
					}
				}
			}
		}()
	}

	// Wait for producers
	time.Sleep(time.Second)
	close(done)
	rb.Close()
	wg.Wait()

	t.Logf("Pushed: %d, Popped: %d", pushed.Load(), popped.Load())
}

func TestByteBufferPool(t *testing.T) {
	pool := NewByteBufferPool(1024)

	// Get buffers
	buf1 := pool.Get()
	buf2 := pool.Get()

	if len(buf1) != 1024 {
		t.Errorf("Expected buffer length 1024, got %d", len(buf1))
	}

	// Modify and return
	buf1[0] = 42
	pool.Put(buf1)

	// Get again - should be cleared
	buf3 := pool.Get()
	if buf3[0] != 0 {
		t.Error("Buffer was not cleared before returning to pool")
	}

	pool.Put(buf2)
	pool.Put(buf3)
}

func TestWorkerPool_Submit(t *testing.T) {
	var processed atomic.Int64

	handler := func(ctx context.Context, work *PacketWork) error {
		processed.Add(1)
		return nil
	}

	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    2,
		QueueSize:     100,
		MaxPacketSize: 1024,
		Handler:       handler,
	})

	pool.Start()

	// Submit work
	for i := 0; i < 50; i++ {
		data := []byte{byte(i)}
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		pool.Submit(data, 1, addr)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	pool.Stop()

	if processed.Load() != 50 {
		t.Errorf("Expected 50 processed, got %d", processed.Load())
	}
}

func TestWorkerPool_Drop(t *testing.T) {
	var dropped atomic.Int64

	handler := func(ctx context.Context, work *PacketWork) error {
		time.Sleep(10 * time.Millisecond) // Slow handler
		return nil
	}

	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    1,
		QueueSize:     4, // Small queue
		MaxPacketSize: 64,
		Handler:       handler,
		DropCallback: func(w PacketWork) {
			dropped.Add(1)
		},
	})

	pool.Start()

	// Submit more work than queue can hold
	for i := 0; i < 20; i++ {
		data := []byte{byte(i)}
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		pool.Submit(data, 1, addr)
	}

	// Some should have been dropped
	time.Sleep(50 * time.Millisecond)
	pool.Stop()

	if dropped.Load() == 0 {
		t.Error("Expected some packets to be dropped")
	}
	t.Logf("Dropped: %d", dropped.Load())
}
