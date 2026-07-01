// LICENSE: clock
package testclock

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/stretchr/testify/require"
)

// Clock provides facilities to manipulate time, timers, and tickers. It
// is designed for use in deterministic testing of time reliant code. Since
// deterministism is hard to achieve when influencing a clock from multiple
// goroutines, the FakeClock disallows concurrent access by-design.
type Clock struct {
	backend testBackend

	// This variable is only used to aid detection of concurrent calls by
	// the race detector. It is unused otherwise.
	detectConcurrentCalls int
}

type Option func(*testBackend)

func WithNow(now time.Time) Option {
	return Option(func(b *testBackend) {
		b.now = now
	})
}

func WithLocation(loc *time.Location) Option {
	return Option(func(b *testBackend) {
		b.now = b.now.In(loc)
	})
}

func New(opts ...Option) *Clock {
	now := time.Now().Truncate(time.Second)

	st := &Clock{
		backend: testBackend{
			now: now,
		},
	}

	for _, opt := range opts {
		opt(&st.backend)
	}

	st.backend.cond.L = &st.backend.mu
	return st
}

// Clock returns a clock controlled by the test clock.
func (st *Clock) Clock() clock.Clock {
	return clock.New(&st.backend)
}

// Block waits until there are at least the given count of tickers/timers pending.
func (st *Clock) Block(t *testing.T, pendingTimerCount int) {
	st.detectConcurrentCalls++
	st.backend.block(t, pendingTimerCount)
}

// Next returns how much time needs to elapse to fire the next pending timer.
// It returns a negative duration if there are no pending timers.
func (st *Clock) Next() time.Duration {
	st.detectConcurrentCalls++
	return st.backend.next()
}

// Step steps the clock far enough to trigger the the next pending
// timer/ticker. It returns (elapsed,true) if successful or (0, false) if there
// were no timers/tickers pending. Block can be called first to ensure there is
// one or more pending timers/tickers.
func (st *Clock) Step() (time.Duration, bool) {
	st.detectConcurrentCalls++
	return st.backend.step()
}

// Advance moves the clock forward and returns the number of pending timers
// that were triggered.
func (st *Clock) Advance(d time.Duration) int {
	st.detectConcurrentCalls++
	return st.backend.advance(d)
}

// AdvanceTo moves the clock forward to the specific time and returns the
// number of pending timers that were triggered.
func (st *Clock) AdvanceTo(t time.Time) int {
	st.detectConcurrentCalls++
	return st.backend.advanceTo(t)
}

func (st *Clock) BlockThenAdvance(t *testing.T, pendingTimerCount int, d time.Duration) int {
	st.Block(t, pendingTimerCount)
	return st.Advance(d)
}

func (st *Clock) BlockThenStep(t *testing.T, pendingTimerCount int) (time.Duration, bool) {
	st.Block(t, pendingTimerCount)
	return st.Step()
}

// Now provides functionality equivalent to time.Now according to the
// the test clock.
func (st *Clock) Now() time.Time {
	return st.backend.Now()
}

// Since provides functionality equivalent to time.Since according to the
// the test clock.
func (st *Clock) Since(t time.Time) time.Duration {
	return st.backend.Since(t)
}

type testBackend struct {
	mu        sync.Mutex
	cond      sync.Cond
	now       time.Time
	advancing bool
	timers    timerHeap
}

// Now provides functionality equivalent to time.Now according to the
// the test clock.
func (b *testBackend) Now() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now
}

// Since provides functionality equivalent to time.Since according to the
// the test clock.
func (b *testBackend) Since(t time.Time) time.Duration {
	return b.Now().Sub(t)
}

// NewTicker provides functionality equivalent to time.NewTicker according to
// the test clock.
func (b *testBackend) NewTicker(d time.Duration) clock.Ticker {
	if d <= 0 {
		panic(errors.New("non-positive interval for NewTicker"))
	}
	return &testTicker{timer: b.newTimer(d, false)}
}

// NewTimer provides functionality equivalent to time.NewTimer according to
// the test clock.
func (b *testBackend) NewTimer(d time.Duration) clock.Timer {
	return b.newTimer(d, true)
}

func (b *testBackend) block(t *testing.T, minimumTimerCount int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	go func() {
		<-ctx.Done()
		b.cond.Broadcast()
	}()

	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.timers) < minimumTimerCount {
		if ctx.Err() != nil {
			require.FailNow(t, "timed out waiting for pending timers/tickers", "wanted=%d have=%d", minimumTimerCount, len(b.timers))
			return
		}
		b.cond.Wait()
	}
}

func (b *testBackend) next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.timers) == 0 {
		return -1
	}
	return b.timers[0].when.Sub(b.now)
}

func (b *testBackend) step() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.timers) == 0 {
		return 0, false
	}

	advanceBy := b.timers[0].when.Sub(b.now)
	triggered := b.advanceUnderLock(advanceBy, true)
	if triggered != 1 {
		panic(fmt.Errorf("should have triggered one timer/ticker but triggered %d", triggered))
	}
	return advanceBy, true
}

func (b *testBackend) advance(d time.Duration) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.advanceUnderLock(d, false)
}

func (b *testBackend) advanceTo(t time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.advanceUnderLock(t.Sub(b.now), false)
}

func (b *testBackend) advanceUnderLock(d time.Duration, once bool) int {
	if d < 0 {
		panic(errors.New("negative delta for advance"))
	}

	defer b.detectConcurrentAdvance()()

	now := b.now.Add(d)

	triggered := 0
	for len(b.timers) > 0 {
		timer := b.timers[0]
		if now.Before(timer.when) {
			break
		}

		triggered++
		timer.trigger()

		// Reschedule if the timer is on an interval (i.e. a ticker).
		if timer.interval > 0 {
			timer.when = timer.when.Add(timer.interval)
			heap.Fix(&b.timers, 0)
		} else {
			dropTimer(&b.timers, timer)
		}

		if once {
			break
		}
	}

	b.now = now
	return triggered
}

func (b *testBackend) newTimer(interval time.Duration, oneShot bool) *testTimer {
	b.mu.Lock()
	defer b.mu.Unlock()

	// we panic if the interval is <=0 for a ticker since the tick interval
	// must be non-negative. For timer's though, this is valid and we should
	// treat the timer as expiring now (mimics the runtime)
	if interval < 0 {
		interval = 0
	}

	when := b.now.Add(interval)
	if oneShot {
		// Disable the interval for one-shot timers
		interval = 0
	}

	timer := &testTimer{
		b:        b,
		ch:       make(chan time.Time, 1),
		when:     when,
		interval: interval,
	}

	// If the timer has expired immediately then trigger it. Otherwise, add the
	// new timer to the timers heap and broadcast to wake blockers. Only timers
	// can expire immediately since ticker intervals are always >0.
	if when.Equal(b.now) {
		timer.trigger()
	} else {
		heap.Push(&b.timers, timer)
		b.cond.Broadcast()
	}
	return timer
}

func (b *testBackend) resetTimer(timer *testTimer, d time.Duration) (active bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// we panic if the interval is <0 for a ticker since the tick interval
	// must be non-negative. For timer's though, this is valid and we should
	// treat the timer as expiring now (mimics the runtime)
	if d < 0 {
		d = 0
	}

	timer.when = b.now.Add(d)
	if timer.interval > 0 {
		timer.interval = d
	}

	for i, candidate := range b.timers {
		if candidate == timer {
			heap.Fix(&b.timers, i)
			return true
		}
	}

	heap.Push(&b.timers, timer)
	b.cond.Broadcast()
	return false
}

func (b *testBackend) stopTimer(timer *testTimer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return dropTimer(&b.timers, timer)
}

func (b *testBackend) detectConcurrentAdvance() func() {
	if b.advancing {
		panic(errors.New("concurrent call to Advance/Block/BlockThenAdvance"))
	}
	b.advancing = true
	return func() {
		b.advancing = false
	}
}

type testTimer struct {
	b        *testBackend
	ch       chan time.Time
	when     time.Time
	interval time.Duration
}

// Chan returns a channel on which timer expiry is delivered.
func (timer *testTimer) Chan() <-chan time.Time {
	return timer.ch
}

// Reset provides functionality equivalent to the time.Timer method of the same name.
func (timer *testTimer) Reset(d time.Duration) bool {
	return timer.b.resetTimer(timer, d)
}

// Stop provides functionality equivalent to the time.Timer method of the same name.
func (timer *testTimer) Stop() bool {
	return timer.b.stopTimer(timer)
}

func (timer *testTimer) trigger() {
	// Do a non-blocking send into the buffered channel. This preserves go
	// runtime behavior that the first ticks time is what is present on
	// the channel.
	select {
	case timer.ch <- timer.when:
	default:
	}
}

type testTicker struct {
	timer *testTimer
}

// Chan returns a channel on which ticks are delivered.
func (ticker *testTicker) Chan() <-chan time.Time { return ticker.timer.Chan() }

// Reset provides functionality equivalent to the time.Ticker method of the same name.
func (ticker *testTicker) Reset(d time.Duration) {
	if d <= 0 {
		panic(errors.New("non-positive interval for Ticker.Reset"))
	}
	ticker.timer.Reset(d)
}

// Stop provides functionality equivalent to the time.Ticker method of the same name.
func (ticker *testTicker) Stop() { ticker.timer.Stop() }

func dropTimer(timers *timerHeap, timer *testTimer) (dropped bool) {
	for i, candidate := range *timers {
		if candidate == timer {
			heap.Remove(timers, i)
			return true
		}
	}
	return false
}

type timerHeap []*testTimer

func (h timerHeap) Len() int            { return len(h) }
func (h timerHeap) Less(i, j int) bool  { return h[i].when.Before(h[j].when) }
func (h timerHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *timerHeap) Push(x interface{}) { *h = append(*h, x.(*testTimer)) }

func (h *timerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
