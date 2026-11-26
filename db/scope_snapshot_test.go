package db

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestTaskScopeSnapshot(t *testing.T) {
	d, _, cs := testSetup(t)
	defer d.Close()

	name := fmt.Sprintf("scope-snapshot-%d", time.Now().UnixNano())
	companyID, _, err := cs.UpsertCompany(name, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.DeleteCompany(companyID) //nolint:errcheck

	added, skipped, invalid, errs := cs.AddScope(companyID, []string{
		"company-example.org",
		"203.0.113.7",
		"10.20.0.0/16",
	}, "test")
	if added != 3 || skipped != 0 || invalid != 0 || len(errs) != 0 {
		t.Fatalf("company scope: added=%d skipped=%d invalid=%d errs=%v", added, skipped, invalid, errs)
	}

	tk, err := d.CreateTask("scope snapshot", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID) //nolint:errcheck

	if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, company_id) VALUES ($1,'company',$2)`, tk.ID, companyID); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		kind, domain, net, value string
	}{
		{kind: "root_domain", domain: "root.example.net"},
		{kind: "subdomain", domain: "api.root.example.net"},
		{kind: "ip", net: "192.0.2.5/32"},
		{kind: "cidr", net: "198.51.100.0/24"},
		{kind: "ip", net: "2001:db8::5/128"},
		{kind: "cidr", net: "2001:db8:1::/64"},
		{kind: "icp", value: "icp-123"},
		{kind: "keyword", value: "acme"},
	} {
		if _, err := d.Exec(`INSERT INTO task_scope(task_id, kind, domain, net, value)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,'')::cidr,NULLIF($5,''))`, tk.ID, row.kind, row.domain, row.net, row.value); err != nil {
			t.Fatalf("insert %s: %v", row.kind, err)
		}
	}

	snap, err := d.TaskScopeSnapshot(tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.TaskID != tk.ID {
		t.Fatalf("task id=%d, want %d", snap.TaskID, tk.ID)
	}
	if snap.CompanyID == nil || *snap.CompanyID != companyID {
		t.Fatalf("company id=%v, want %d", snap.CompanyID, companyID)
	}

	wantDomains := []string{"*.root.example.net", "api.root.example.net", "company-example.org", "root.example.net"}
	if !slices.Equal(snap.Domains, wantDomains) {
		t.Fatalf("domains=%v, want %v", snap.Domains, wantDomains)
	}
	wantIPs := []string{"192.0.2.5", "2001:db8::5", "203.0.113.7"}
	if !slices.Equal(snap.IPs, wantIPs) {
		t.Fatalf("ips=%v, want %v", snap.IPs, wantIPs)
	}
	wantCIDRs := []string{"10.20.0.0/16", "198.51.100.0/24", "2001:db8:1::/64"}
	if !slices.Equal(snap.CIDRs, wantCIDRs) {
		t.Fatalf("cidrs=%v, want %v", snap.CIDRs, wantCIDRs)
	}
}

func TestTaskScopeSnapshotEmptyAndMissing(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()

	tk, err := d.CreateTask("scope snapshot empty", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID) //nolint:errcheck

	snap, err := d.TaskScopeSnapshot(tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.CompanyID != nil {
		t.Fatalf("company id=%v, want nil", snap.CompanyID)
	}
	if snap.Domains == nil || snap.IPs == nil || snap.CIDRs == nil {
		t.Fatalf("empty snapshot slices must be non-nil: %+v", snap)
	}
	if len(snap.Domains) != 0 || len(snap.IPs) != 0 || len(snap.CIDRs) != 0 {
		t.Fatalf("empty snapshot has scope: %+v", snap)
	}

	if _, err := d.TaskScopeSnapshot(0); err == nil {
		t.Fatal("task id 0 must fail")
	}
	if _, err := d.TaskScopeSnapshot(9_000_000_000); err == nil {
		t.Fatal("missing task must fail")
	}
}

func TestSplitScopeNet(t *testing.T) {
	for _, tc := range []struct {
		in, ip, cidr string
	}{
		{"192.0.2.5/32", "192.0.2.5", ""},
		{"2001:db8::5/128", "2001:db8::5", ""},
		{"192.0.2.0/24", "", "192.0.2.0/24"},
		{"2001:db8:1::/64", "", "2001:db8:1::/64"},
		{"", "", ""},
	} {
		ip, cidr, err := splitScopeNet(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if ip != tc.ip || cidr != tc.cidr {
			t.Fatalf("%q: ip=%q cidr=%q, want %q/%q", tc.in, ip, cidr, tc.ip, tc.cidr)
		}
	}
	if _, _, err := splitScopeNet("not-a-net"); err == nil {
		t.Fatal("invalid network must fail")
	}
}
