package approvals

import (
	"testing"
	"time"
)

func TestWriteState(t *testing.T) {
	at := time.Now()
	since := at.Add(-clockSkew)
	meta := func(cur int, vs map[int]KVVersion) *KVMeta { return &KVMeta{Current: cur, Versions: vs} }
	patch := Write{Kind: WritePatch, Mount: "secret/", Path: "a", BaseVersion: 3}
	create := Write{Kind: WriteCreate, Mount: "secret/", Path: "b"}
	destroy := Write{Kind: WriteDestroy, Mount: "secret/", Path: "a", Versions: []int{1, 2}}
	for _, tc := range []struct {
		name string
		w    Write
		m    *KVMeta
		want writeOutcome
		ver  int
	}{
		{"patch written", patch, meta(4, map[int]KVVersion{4: {Created: at}}), writeDone, 4},
		{"patch not written", patch, meta(3, map[int]KVVersion{3: {Created: at.Add(-time.Hour)}}), writeNotDone, 0},
		{"patch: v4 older than applying", patch, meta(4, map[int]KVVersion{4: {Created: at.Add(-time.Hour)}}), writeConflict, 0},
		{"patch: someone wrote after", patch, meta(5, map[int]KVVersion{4: {Created: at}, 5: {Created: at}}), writeConflict, 0},
		{"create written", create, meta(1, map[int]KVVersion{1: {Created: at}}), writeDone, 1},
		{"create not written", create, nil, writeNotDone, 0},
		{"destroy done", destroy, meta(3, map[int]KVVersion{1: {Destroyed: true}, 2: {Destroyed: true}}), writeDone, 0},
		{"destroy not done", destroy, meta(3, map[int]KVVersion{1: {}, 2: {}}), writeNotDone, 0},
		{"destroy partial", destroy, meta(3, map[int]KVVersion{1: {Destroyed: true}, 2: {}}), writeConflict, 0},
		{"destroy on a gone path", destroy, nil, writeConflict, 0},
	} {
		got, ver := writeState(tc.w, tc.m, since)
		if got != tc.want || ver != tc.ver {
			t.Errorf("%s: %v v%d, want %v v%d", tc.name, got, ver, tc.want, tc.ver)
		}
	}
}
