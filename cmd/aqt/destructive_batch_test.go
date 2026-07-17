package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

type fakeSnapshotPruner struct {
	snapshots []api.SnapshotInfo
	deleted   []string
	fail      map[string]error
}

func (f *fakeSnapshotPruner) ListSnapshots(string) ([]api.SnapshotInfo, error) {
	return f.snapshots, nil
}

func (f *fakeSnapshotPruner) DeleteSnapshot(id string) error {
	f.deleted = append(f.deleted, id)
	return f.fail[id]
}

func TestSnapshotPruneDryRunExplicitIDsNeverDeletes(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	cl := &fakeSnapshotPruner{snapshots: []api.SnapshotInfo{{ID: "one"}}}
	if err := runSnapshotPrune(cl, nil, []string{"one"}, "", "", 0, "", true, true); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(cl.deleted) != 0 {
		t.Fatalf("dry run deleted %v", cl.deleted)
	}
}

func TestSnapshotPrunePreflightsLateBlocker(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	cl := &fakeSnapshotPruner{snapshots: []api.SnapshotInfo{
		{ID: "deletable"},
		{ID: "anchored", Anchored: true},
	}}
	err := runSnapshotPrune(cl, nil, []string{"deletable", "anchored"}, "", "", 0, "", false, true)
	if err == nil {
		t.Fatal("prune with anchored snapshot succeeded")
	}
	if len(cl.deleted) != 0 {
		t.Fatalf("preflight blocker allowed deletes: %v", cl.deleted)
	}
}

func TestSnapshotPruneDeduplicatesExplicitIDs(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	cl := &fakeSnapshotPruner{snapshots: []api.SnapshotInfo{{ID: "one"}}}
	if err := runSnapshotPrune(cl, nil, []string{"one", "one"}, "", "", 0, "", false, true); err != nil {
		t.Fatalf("prune duplicate ids: %v", err)
	}
	if want := []string{"one"}; !reflect.DeepEqual(cl.deleted, want) {
		t.Fatalf("deleted = %v, want %v", cl.deleted, want)
	}
}

type fakeDeviceRemover struct {
	devices []api.Device
	deleted []string
	fail    map[string]error
}

func (f *fakeDeviceRemover) ListDevices() ([]api.Device, error) { return f.devices, nil }

func (f *fakeDeviceRemover) DeleteDevice(id string) error {
	f.deleted = append(f.deleted, id)
	return f.fail[id]
}

func TestDeviceBatchRevokesCurrentDeviceLastAndClearsOnLostResponse(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	lost := errors.New("response lost")
	cl := &fakeDeviceRemover{
		devices: []api.Device{{ID: "self"}, {ID: "other"}},
		fail:    map[string]error{"self": lost},
	}
	cleared := 0
	err := runDevicesRemoveWithClient(cl, "self", []string{"self", "other"}, func() error {
		cleared++
		return nil
	})
	if !errors.Is(err, lost) {
		t.Fatalf("error = %v, want response-lost error", err)
	}
	if want := []string{"other", "self"}; !reflect.DeepEqual(cl.deleted, want) {
		t.Fatalf("delete order = %v, want %v", cl.deleted, want)
	}
	if cleared != 1 {
		t.Fatalf("session clears = %d, want 1", cleared)
	}
}

func TestDeviceBatchStopsAfterMidBatchFailure(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	boom := errors.New("network down")
	cl := &fakeDeviceRemover{
		devices: []api.Device{{ID: "one"}, {ID: "two"}, {ID: "three"}},
		fail:    map[string]error{"two": boom},
	}
	var err error
	out := captureStdout(t, func() {
		err = runDevicesRemoveWithClient(cl, "", []string{"one", "two", "three"}, func() error { return nil })
	})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want network failure", err)
	}
	if want := []string{"one", "two"}; !reflect.DeepEqual(cl.deleted, want) {
		t.Fatalf("attempted deletes = %v, want %v", cl.deleted, want)
	}
	var report destructiveBatchReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, out)
	}
	got := make([]string, len(report.Results))
	for i, result := range report.Results {
		got[i] = result.Status
	}
	if want := []string{batchSucceeded, batchFailed, batchNotAttempted}; !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
}

func TestDeviceBatchDeduplicatesIDs(t *testing.T) {
	previous := flagJSON
	flagJSON = true
	defer func() { flagJSON = previous }()

	cl := &fakeDeviceRemover{devices: []api.Device{{ID: "one"}}}
	if err := runDevicesRemoveWithClient(cl, "", []string{"one", "one"}, func() error { return nil }); err != nil {
		t.Fatalf("remove duplicate ids: %v", err)
	}
	if want := []string{"one"}; !reflect.DeepEqual(cl.deleted, want) {
		t.Fatalf("deleted = %v, want %v", cl.deleted, want)
	}
}
