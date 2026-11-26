package db

import (
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ScopeSnapshot is the network-authorization read model for one task. It is
// intentionally independent of the web/asset scope semantics: only entries
// that grant access to a host or network are included. ICP and keyword scope
// rows are ignored because they cannot authorize a network target.
type ScopeSnapshot struct {
	TaskID    int64
	CompanyID *int64
	Domains   []string
	IPs       []string
	CIDRs     []string
}

// TaskScopeSnapshot reads a task's scope rows and expands company scope rules
// into concrete domains and networks. The result is normalized, deduplicated,
// and sorted so the caller can canonicalize it for signing.
//
// Rules:
//   - root_domain emits the apex and its wildcard (*.example.com);
//   - subdomain emits the exact host only;
//   - ip/cidr rows split /32 and /128 into IPs, wider networks into CIDRs;
//   - company rows join company_scope domain/ip/cidr rules;
//   - icp/keyword rows are ignored.
func (d *DB) TaskScopeSnapshot(taskID int64) (ScopeSnapshot, error) {
	snap := ScopeSnapshot{
		TaskID:  taskID,
		Domains: []string{},
		IPs:     []string{},
		CIDRs:   []string{},
	}
	if taskID <= 0 {
		return snap, fmt.Errorf("task_id is required")
	}

	var taskCompany sql.NullInt64
	if err := d.QueryRow(`SELECT company_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&taskCompany); err != nil {
		if err == sql.ErrNoRows {
			return snap, fmt.Errorf("task %d not found", taskID)
		}
		return snap, err
	}

	rows, err := d.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(company_id,0)
FROM task_scope WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return snap, err
	}
	type scopeRow struct {
		kind      string
		domain    string
		netText   string
		companyID int64
	}
	var scopeRows []scopeRow
	for rows.Next() {
		var r scopeRow
		if err := rows.Scan(&r.kind, &r.domain, &r.netText, &r.companyID); err != nil {
			_ = rows.Close()
			return snap, err
		}
		scopeRows = append(scopeRows, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return snap, err
	}
	if err := rows.Close(); err != nil {
		return snap, err
	}

	domains := map[string]struct{}{}
	ips := map[string]struct{}{}
	cidrs := map[string]struct{}{}
	companyIDs := map[int64]struct{}{}
	addDomain := func(raw string) {
		d := normalizeSnapshotDomain(raw)
		if d != "" {
			domains[d] = struct{}{}
		}
	}
	addRootDomain := func(raw string) {
		d := normalizeSnapshotDomain(raw)
		if d == "" {
			return
		}
		domains[d] = struct{}{}
		domains["*."+d] = struct{}{}
	}
	addNet := func(raw string) error {
		ip, cidr, err := splitScopeNet(raw)
		if err != nil {
			return err
		}
		if ip != "" {
			ips[ip] = struct{}{}
		}
		if cidr != "" {
			cidrs[cidr] = struct{}{}
		}
		return nil
	}

	for _, r := range scopeRows {
		switch r.kind {
		case "company":
			if r.companyID > 0 {
				companyIDs[r.companyID] = struct{}{}
			}
		case "root_domain":
			addRootDomain(r.domain)
		case "subdomain":
			addDomain(r.domain)
		case "ip", "cidr":
			if err := addNet(r.netText); err != nil {
				return snap, fmt.Errorf("task_scope %s: %w", r.kind, err)
			}
		}
	}

	if len(companyIDs) > 0 {
		ids := make([]int64, 0, len(companyIDs))
		for id := range companyIDs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if !taskCompany.Valid {
			id := ids[0]
			taskCompany = sql.NullInt64{Int64: id, Valid: true}
		}
		for _, id := range ids {
			crows, err := d.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'')
FROM company_scope WHERE company_id=$1 ORDER BY id`, id)
			if err != nil {
				return snap, err
			}
			for crows.Next() {
				var kind, domain, netText string
				if err := crows.Scan(&kind, &domain, &netText); err != nil {
					crows.Close()
					return snap, err
				}
				switch kind {
				case "domain":
					// company_scope.domain is a registrable root domain; keep the
					// exact name here. A wildcard would silently authorize every
					// subdomain, which is the root_domain row's explicit job.
					addDomain(domain)
				case "ip", "cidr":
					if err := addNet(netText); err != nil {
						crows.Close()
						return snap, fmt.Errorf("company_scope %s: %w", kind, err)
					}
				}
			}
			err = crows.Err()
			crows.Close()
			if err != nil {
				return snap, err
			}
		}
	}

	if taskCompany.Valid && taskCompany.Int64 > 0 {
		id := taskCompany.Int64
		snap.CompanyID = &id
	}
	snap.Domains = sortedSet(domains)
	snap.IPs = sortedSet(ips)
	snap.CIDRs = sortedSet(cidrs)
	return snap, nil
}

// normalizeSnapshotDomain lowercases and strips a trailing dot. A leading
// wildcard is removed because callers decide whether to emit one.
func normalizeSnapshotDomain(raw string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	d = strings.TrimPrefix(d, "*.")
	return d
}

// splitScopeNet turns a CIDR into either a single IP (/32, /128) or a network.
func splitScopeNet(raw string) (ipOut, cidrOut string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", nil
	}
	_, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid network %q", raw)
	}
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		return ipnet.IP.String(), "", nil
	}
	return "", ipnet.String(), nil
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
