// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// A declared header length is a claim until the bytes arrive. A body that declares
// the cap and then ends must cost what it sent, not the 32 MiB it claimed.
func TestDecodeEnvelopeAllocatesWhatArrives(t *testing.T) {
	body := binary.BigEndian.AppendUint32(nil, maxWireHeader)
	body = append(body, `{"id":"x"`...)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := DecodeResourceUpload(bytes.NewReader(body))
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("a truncated header must be rejected")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("decoding %d bytes allocated %d bytes", len(body), grew)
	}
}
