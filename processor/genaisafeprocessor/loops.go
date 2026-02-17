package genaisafeprocessor

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// LoopDetector tracks repeated prompts to detect infinite loops.
type LoopDetector struct {
	mu        sync.Mutex
	threshold int
	// counts tracks hash → count for each trace_id
	counts map[string]map[string]int
}

// NewLoopDetector creates a loop detector.
func NewLoopDetector(threshold int) *LoopDetector {
	return &LoopDetector{
		threshold: threshold,
		counts:    make(map[string]map[string]int),
	}
}

// Check records a prompt and returns true if a loop is detected.
func (d *LoopDetector) Check(traceID string, prompt string) (loopDetected bool, count int) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(prompt)))[:16]

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.counts[traceID] == nil {
		d.counts[traceID] = make(map[string]int)
	}

	d.counts[traceID][hash]++
	count = d.counts[traceID][hash]

	return count >= d.threshold, count
}

// Clear removes tracking data for a trace.
func (d *LoopDetector) Clear(traceID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.counts, traceID)
}

// ActiveTraces returns the number of traces being tracked.
func (d *LoopDetector) ActiveTraces() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.counts)
}