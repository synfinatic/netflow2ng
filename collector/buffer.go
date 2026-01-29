package collector

import (
	"sync"
)

// ByteBufferPool provides a pool of reusable byte buffers to reduce GC pressure
type ByteBufferPool struct {
	pool       sync.Pool
	bufferSize int
}

// NewByteBufferPool creates a new byte buffer pool with the specified buffer size
func NewByteBufferPool(bufferSize int) *ByteBufferPool {
	return &ByteBufferPool{
		bufferSize: bufferSize,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, bufferSize)
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *ByteBufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (p *ByteBufferPool) Put(buf []byte) {
	// Only return buffers of the correct capacity
	bufCap := cap(buf)
	if bufCap >= p.bufferSize {
		// Extend slice to full capacity for clearing and returning
		fullBuf := buf[:bufCap]
		// Clear only up to bufferSize
		for i := 0; i < p.bufferSize; i++ {
			fullBuf[i] = 0
		}
		p.pool.Put(fullBuf[:p.bufferSize])
	}
}

// WorkItemPool provides a pool of reusable PacketWork objects
type WorkItemPool struct {
	pool sync.Pool
}

// NewWorkItemPool creates a new work item pool
func NewWorkItemPool() *WorkItemPool {
	return &WorkItemPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &PacketWork{}
			},
		},
	}
}

// Get retrieves a work item from the pool
func (p *WorkItemPool) Get() *PacketWork {
	return p.pool.Get().(*PacketWork)
}

// Put returns a work item to the pool
func (p *WorkItemPool) Put(work *PacketWork) {
	// Clear the work item before returning
	work.Data = nil
	work.Length = 0
	work.RemoteAddr = nil
	p.pool.Put(work)
}

// FlowBufferPool provides a pool of reusable flow message buffers
type FlowBufferPool struct {
	pool       sync.Pool
	bufferSize int
}

// NewFlowBufferPool creates a new flow buffer pool
func NewFlowBufferPool(bufferSize int) *FlowBufferPool {
	return &FlowBufferPool{
		bufferSize: bufferSize,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, bufferSize)
			},
		},
	}
}

// Get retrieves a flow buffer from the pool
func (p *FlowBufferPool) Get() []byte {
	return p.pool.Get().([]byte)[:0]
}

// Put returns a flow buffer to the pool
func (p *FlowBufferPool) Put(buf []byte) {
	if cap(buf) >= p.bufferSize {
		p.pool.Put(buf[:0])
	}
}
