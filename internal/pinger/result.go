// SPDX-License-Identifier: GPL-2.0-or-later

package pinger

import "time"

// Result holds the outcome of pinging a single host.
type Result struct {
	Sent, Recv    int
	Sum, Min, Max time.Duration // round-trip times of received replies
	TTL           int           // TTL / hop limit of the last reply, 0 if unknown

	adaptForced bool
}

func (r *Result) addReply(rtt time.Duration) {
	if r.Recv == 0 || rtt < r.Min {
		r.Min = rtt
	}
	r.Max = max(r.Max, rtt)
	r.Sum += rtt
	r.Recv++
}

// Alive reports whether at least one reply was received.
func (r *Result) Alive() bool { return r != nil && r.Recv > 0 }

// Avg is the average round-trip time, 0 if there were no replies.
func (r *Result) Avg() time.Duration {
	if r == nil || r.Recv == 0 {
		return 0
	}
	return r.Sum / time.Duration(r.Recv)
}

// Lost is the number of probes without a reply.
func (r *Result) Lost() int { return r.Sent - r.Recv }

// LossPercent is the packet loss in percent; 100 if nothing was received.
func (r *Result) LossPercent() int {
	if r.Recv == 0 || r.Sent == 0 {
		return 100
	}
	return r.Lost() * 100 / r.Sent
}

// TimeoutAdaptable reports whether the RTT statistics are trustworthy enough
// to shorten subsequent port timeouts.
func (r *Result) TimeoutAdaptable() bool {
	return r != nil && (r.Recv > 2 || r.adaptForced && r.Recv > 0)
}

// Merge adds all probes and statistics of o into r.
func (r *Result) Merge(o *Result) {
	if o == nil {
		return
	}
	if o.Recv > 0 {
		if r.Recv == 0 || o.Min < r.Min {
			r.Min = o.Min
		}
		r.Max = max(r.Max, o.Max)
		if o.TTL > 0 {
			r.TTL = o.TTL
		}
	}
	r.Sent += o.Sent
	r.Recv += o.Recv
	r.Sum += o.Sum
	r.adaptForced = r.adaptForced || o.adaptForced
}
