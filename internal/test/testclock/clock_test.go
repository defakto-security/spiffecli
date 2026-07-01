// LICENSE: clock
package testclock

import (
	"context"
	"testing"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDuration = time.Minute

	// Tests should run under this time. Normally it should take
	// sub-millisecond but things can happen under CI/CD load that could
	// make this higher. As long as this is less than testDuration, things
	// should be ok.
	failAfter = 2 * time.Second
)

var (
	testDate = time.Date(2022, time.December, 20, 0, 0, 0, 0, time.UTC)
)

func TestNow(t *testing.T) {
	testBoth(t,
		func(t *testing.T, clk clock.Clock) {
			now := time.Now()
			require.NotEqual(t, now.String(), testDate.String())
		},
		func(t *testing.T, clk clock.Clock, testClk *Clock) {
			before := clk.Now()
			testClk.Advance(testDuration)
			after := clk.Now()
			assert.Equal(t, testDate.String(), before.String())
			assert.Equal(t, testDuration, after.Sub(before))
		},
	)
}

func TestSince(t *testing.T) {
	testBoth(t,
		func(t *testing.T, clk clock.Clock) {
			before := time.Now()
			time.Sleep(time.Millisecond * 50)
			since := clk.Since(before)
			assert.Greater(t, since, time.Duration(0))
		},
		func(t *testing.T, clk clock.Clock, testClk *Clock) {
			before := clk.Now()
			testClk.Advance(testDuration)
			since := clk.Since(before)
			assert.Equal(t, testDuration, since)
		},
	)
}

func TestTicker(t *testing.T) {
	testBoth(t,
		func(t *testing.T, clk clock.Clock) {
			ticker := clk.NewTicker(time.Millisecond)
			defer ticker.Stop()
			<-ticker.Chan()
			<-ticker.Chan()
			<-ticker.Chan()
		},
		func(t *testing.T, clk clock.Clock, testClk *Clock) {
			now := testClk.Now()

			var times []time.Time

			ticker := clk.NewTicker(testDuration)
			defer ticker.Stop()

			select {
			case <-ticker.Chan():
				t.Fatal("ticker should not be ticked")
			default:
			}

			testClk.BlockThenAdvance(t, 1, testDuration/2)
			select {
			case <-ticker.Chan():
				t.Fatal("ticker should not be ticked")
			default:
			}

			testClk.BlockThenAdvance(t, 1, testDuration/2)
			times = append(times, <-ticker.Chan())
			testClk.BlockThenAdvance(t, 1, testDuration)
			times = append(times, <-ticker.Chan())
			testClk.BlockThenAdvance(t, 1, testDuration)
			times = append(times, <-ticker.Chan())

			select {
			case <-ticker.Chan():
				t.Fatal("ticker should not be ticked")
			default:
			}

			require.Equal(t, []time.Time{
				now.Add(1 * testDuration),
				now.Add(2 * testDuration),
				now.Add(3 * testDuration),
			}, times)

		},
	)
}

func TestTimer(t *testing.T) {
	assertStopAndResetReturnValues := func(t *testing.T, timer clock.Timer) {
		assert.False(t, timer.Stop(), "timer should have already expired")
		assert.False(t, timer.Reset(testDuration), "timer should be stopped at the time of reset")
		assert.True(t, timer.Stop(), "timer should still be active because it was just reset")
		assert.False(t, timer.Reset(testDuration), "timer should not be active because it was just stopped")
		assert.True(t, timer.Reset(testDuration), "timer should be active since it was just reset")

	}

	testBoth(t,
		func(t *testing.T, clk clock.Clock) {
			timer := clk.NewTimer(time.Millisecond)
			defer timer.Stop()
			<-timer.Chan()
			assert.False(t, timer.Reset(time.Millisecond))
			<-timer.Chan()
			assert.False(t, timer.Reset(time.Millisecond))
			<-timer.Chan()

			assertStopAndResetReturnValues(t, timer)

		},
		func(t *testing.T, clk clock.Clock, testClk *Clock) {
			now := testClk.Now()

			var times []time.Time

			var wg conc.WaitGroup
			wg.Go(func() {
				timer := clk.NewTimer(testDuration)
				defer timer.Stop()
				times = append(times, <-timer.Chan())
				assert.False(t, timer.Reset(testDuration))
				times = append(times, <-timer.Chan())
				assert.False(t, timer.Reset(testDuration))
				times = append(times, <-timer.Chan())

				assertStopAndResetReturnValues(t, timer)
			})

			testClk.BlockThenAdvance(t, 1, testDuration)
			testClk.BlockThenAdvance(t, 1, testDuration)
			testClk.BlockThenAdvance(t, 1, testDuration)

			wg.Wait()

			require.Equal(t, []time.Time{
				now.Add(1 * testDuration),
				now.Add(2 * testDuration),
				now.Add(3 * testDuration),
			}, times)

		},
	)
}

func TestSleep(t *testing.T) {
	testBoth(t,
		func(t *testing.T, clk clock.Clock) {
			clk.Sleep(context.Background(), time.Millisecond)
		},
		func(t *testing.T, clk clock.Clock, testClk *Clock) {
			var wg conc.WaitGroup
			defer wg.Wait()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wg.Go(func() { testClk.BlockThenAdvance(t, 1, testDuration) })
			assert.True(t, clk.Sleep(ctx, testDuration))

			cancel()

			assert.False(t, clk.Sleep(ctx, time.Hour))
		},
	)
}

func testBoth(t *testing.T,
	realTest func(t *testing.T, clk clock.Clock),
	fakeTest func(t *testing.T, clk clock.Clock, testClk *Clock)) {

	t.Run("real clock", func(t *testing.T) {
		start := time.Now()
		realTest(t, clock.Clock{})
		assert.Less(t, time.Since(start), failAfter, "test did not execute fast enough")
	})

	t.Run("test clock", func(t *testing.T) {
		testClk := New(WithNow(testDate))
		start := time.Now()
		fakeTest(t, testClk.Clock(), testClk)
		assert.Less(t, time.Since(start), failAfter, "test did not execute fast enough")
	})
}
