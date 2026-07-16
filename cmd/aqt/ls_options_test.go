package main

import (
	"reflect"
	"testing"
)

func TestSelectResourceRowsFiltersAndSorts(t *testing.T) {
	rows := []lsRow{
		{ID: "a", Name: "Alpha.txt", Kind: "file", Size: 10, Visibility: "private", UpdatedAt: 100},
		{ID: "b", Name: "beta", Kind: "folder", Size: 0, Visibility: "private", UpdatedAt: 300},
		{ID: "c", Name: "alphabet.bin", Kind: "file", Size: 30, Visibility: "public", UpdatedAt: 200},
	}
	got, err := selectResourceRows(rows, lsOptions{filter: "ALPHA", kind: "file", sortBy: "size"})
	if err != nil {
		t.Fatal(err)
	}
	if ids := []string{got[0].ID, got[1].ID}; !reflect.DeepEqual(ids, []string{"c", "a"}) {
		t.Fatalf("filtered size sort ids = %v, want [c a]", ids)
	}

	got, err = selectResourceRows(rows, lsOptions{visibility: "private", sortBy: "date", reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if ids := []string{got[0].ID, got[1].ID}; !reflect.DeepEqual(ids, []string{"a", "b"}) {
		t.Fatalf("reversed date sort ids = %v, want [a b]", ids)
	}
}

func TestSelectResourceRowsRejectsInvalidFlags(t *testing.T) {
	for _, opts := range []lsOptions{
		{sortBy: "bogus"},
		{sortBy: "name", kind: "archive"},
		{sortBy: "name", visibility: "secret"},
	} {
		if _, err := selectResourceRows(nil, opts); err == nil {
			t.Fatalf("options %+v unexpectedly accepted", opts)
		}
	}
}
