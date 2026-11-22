package spoofhost

import (
	"math"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

// Quality evidence is deliberately lightweight authenticated probe telemetry,
// NOT a throughput benchmark or unverified observation of the underlying ISP.
type pathQuality struct {
	Attempts             uint64
	Successes            uint64
	Misses               uint64
	RTTms                float64
	Jitterms             float64
	LastSuccess          time.Time
	ConsecutiveSuccesses int
}

func (q *pathQuality) success(rtt time.Duration, at time.Time) {
	q.Attempts++
	q.Successes++
	millis := float64(rtt) / float64(time.Millisecond)
	if millis < 0 {
		millis = 0
	}
	if q.Successes == 1 {
		q.RTTms = millis
	} else {
		delta := math.Abs(millis - q.RTTms)
		q.Jitterms = q.Jitterms*0.75 + delta*0.25
		q.RTTms = q.RTTms*0.75 + millis*0.25
	}
	q.LastSuccess = at
	q.ConsecutiveSuccesses++
}
func (q *pathQuality) missed() {
	q.Attempts++
	q.Misses++
	q.ConsecutiveSuccesses = 0
}
func (q pathQuality) lossPercent() float64 {
	if q.Attempts == 0 {
		return 0
	}
	return 100 * float64(q.Misses) / float64(q.Attempts)
}
func (q pathQuality) score() float64 {
	if q.Successes == 0 {
		return math.Inf(1)
	}
	return q.RTTms*(1+2*q.lossPercent()/100) + 1.5*q.Jitterms
}

// pathQualityState compares routes only after independently authenticated,
// repeated successes; momentary differences cannot thrash an active Link.
type pathQualityState struct {
	metrics    map[carrier.SourcePath]*pathQuality
	lastSwitch time.Time
}

func (q *pathQualityState) forPath(p carrier.SourcePath) *pathQuality {
	if q.metrics == nil {
		q.metrics = make(map[carrier.SourcePath]*pathQuality)
	}
	x, ok := q.metrics[p]
	if !ok {
		x = &pathQuality{}
		q.metrics[p] = x
	}
	return x
}
func (q *pathQualityState) reportSuccess(p carrier.SourcePath, rtt time.Duration, now time.Time) {
	q.forPath(p).success(rtt, now)
}
func (q *pathQualityState) reportMiss(p carrier.SourcePath) {
	// Do not indefinitely retain unconfirmed failed scans. Only paths with
	// verified historical success should occupy quality history.
	if prior := q.metrics[p]; prior != nil {
		prior.missed()
	}
}
func (q *pathQualityState) shouldSwitch(current, alternative carrier.SourcePath, now time.Time) bool {
	if current == alternative {
		return false
	}
	challenger := q.metrics[alternative]
	if challenger == nil || challenger.ConsecutiveSuccesses < 3 ||
		now.Sub(challenger.LastSuccess) > 30*time.Second ||
		(!q.lastSwitch.IsZero() && now.Sub(q.lastSwitch) < 20*time.Second) {
		return false
	}
	baseline := q.metrics[current]
	if baseline == nil || baseline.Successes < 2 {
		return false
	}
	// If the current path has repeatedly failed, prefer a recently verified
	// replacement. Otherwise require a sustained material quality improvement.
	if baseline.Misses >= 2 && now.Sub(baseline.LastSuccess) > 6*time.Second {
		return true
	}
	return challenger.score() < baseline.score()*0.78 &&
		challenger.lossPercent() <= baseline.lossPercent()+5
}
func (q *pathQualityState) switched(now time.Time) { q.lastSwitch = now }
