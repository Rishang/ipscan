// SPDX-License-Identifier: GPL-2.0-or-later

package fetcher

import (
	"context"

	"github.com/noobi/ipscan-go/internal/model"
)

// Run scans one host with the given fetchers and returns the result.
//
// When pinging is enabled the host is pinged first; dead hosts get NotScanned
// for all remaining columns unless scan_dead_hosts is set. When pinging is
// disabled every host is treated as alive. Once ctx is cancelled the remaining
// columns are NotScanned.
func Run(ctx context.Context, h *Host, fetchers []Fetcher) *model.Result {
	r := model.NewResult(h.Addr, len(fetchers))
	skip := false
	if h.env.Pinger != nil {
		if p := h.Ping(ctx); !p.Alive() && !h.env.Cfg.Scanner.ScanDeadHosts {
			skip = true
		}
	} else {
		h.setType(model.Alive)
	}
	for i, f := range fetchers {
		if i > 0 && (ctx.Err() != nil || skip && f.ID() != "ping" && f.ID() != "packetloss" && f.ID() != "ttl") {
			continue // stays NotScanned
		}
		r.Values[i] = f.Scan(ctx, h)
	}
	r.MAC = h.mac
	r.Type = h.Type
	if r.Type == model.Unknown {
		r.Type = model.Dead
	}
	return r
}
