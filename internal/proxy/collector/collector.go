package collector

import (
	"runtime"
	"time"

	"github.com/datadog/datadog-go/statsd"
)

// Collector ticks periodically and emits runtime stats to datadog
type Collector struct {
	// interval represents the interval inbetween ticks for stats collection
	interval time.Duration

	// done, when closed, is used to signal the closure of the runtime polling goroutine
	done chan struct{}

	// statsd client used to send metrics
	client *statsd.Client
}

// New creates a new collector that will periodically emit runtime statistics to datadog.
func New(client *statsd.Client, interval time.Duration) *Collector {
	return &Collector{
		interval: interval,
		client:   client,
		done:     make(chan struct{}),
	}
}

// Run gathers statistics from package runtime and emits them to statsd via client
func (c *Collector) Run() {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-tick.C:
			c.emitStats()
		}
	}
}

// Close signals the collector to close the polling goroutine, use for graceful shutdowns
func (c *Collector) Close() {
	close(c.done)
}

func (c *Collector) emitStats() {
	c.emitCPUStats()
	c.emitMemStats()
}

func (c *Collector) emitCPUStats() {
	c.gauge("cpu.goroutines", uint64(runtime.NumGoroutine()))
	c.gauge("cpu.cgo_calls", uint64(runtime.NumCgoCall()))
}

func (c *Collector) emitMemStats() {
	m := &runtime.MemStats{}
	runtime.ReadMemStats(m)

	// General
	c.gauge("mem.alloc", m.Alloc)
	c.gauge("mem.total", m.TotalAlloc)
	c.gauge("mem.sys", m.Sys)
	c.gauge("mem.lookups", m.Lookups)
	c.gauge("mem.malloc", m.Mallocs)
	c.gauge("mem.frees", m.Frees)

	// Heap
	c.gauge("mem.heap.alloc", m.HeapAlloc)
	c.gauge("mem.heap.sys", m.HeapSys)
	c.gauge("mem.heap.idle", m.HeapIdle)
	c.gauge("mem.heap.inuse", m.HeapInuse)
	c.gauge("mem.heap.released", m.HeapReleased)
	c.gauge("mem.heap.objects", m.HeapObjects)

	// Stack
	c.gauge("mem.stack.inuse", m.StackInuse)
	c.gauge("mem.stack.sys", m.StackSys)
	c.gauge("mem.stack.mspan_inuse", m.MSpanInuse)
	c.gauge("mem.stack.mspan_sys", m.MSpanSys)
	c.gauge("mem.stack.mcache_inuse", m.MCacheInuse)
	c.gauge("mem.stack.mcache_sys", m.MCacheSys)

	// Garbage Collection
	c.gauge("mem.gc.sys", m.GCSys)
	c.gauge("mem.gc.next", m.NextGC)
	c.gauge("mem.gc.last", m.LastGC)
	c.gauge("mem.gc.pause_total", m.PauseTotalNs)
	c.gauge("mem.gc.pause", m.PauseNs[(m.NumGC+255)%256])
	c.gauge("mem.gc.count", uint64(m.NumGC))

	// Other
	c.gauge("mem.othersys", m.OtherSys)
}

func (c *Collector) gauge(key string, val uint64) {
	c.client.Gauge(key, float64(val), nil, 1.0)
}
