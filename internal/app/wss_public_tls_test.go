package app

import (
	"context"
	"testing"
)

func TestPublicTLSWSSModeBindsOriginalEngineIdentity(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	link := journalTestLink(t)
	link.WSS.PublicTLS = true
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Ensure(ctx, link)
	if err != nil || !result.Changed {
		t.Fatalf("public TLS initial ensure: %+v %v", result, err)
	}
	snap := mustLoadCrashSnapshot(t, store)
	record, ok := snap.Find(link.ID)
	if !ok || !record.Desired.WSS.PublicTLS || len(snap.WSSCrashOperations) != 0 {
		t.Fatal("public TLS Link mode was not persisted through the canonical journal")
	}
	count := host.applyCount
	result, err = engine.Ensure(ctx, link)
	if err != nil || result.Changed || host.applyCount != count {
		t.Fatal("public TLS idempotent Ensure changed the committed Link")
	}
	changed := link
	changed.WSS.PublicTLS = false
	if _, err = engine.Ensure(ctx, changed); err == nil || host.applyCount != count {
		t.Fatal("an in-place WSS authentication-mode change reached host Apply")
	}
	snap = mustLoadCrashSnapshot(t, store)
	record, ok = snap.Find(link.ID)
	if !ok || !record.Desired.WSS.PublicTLS {
		t.Fatal("mode mismatch changed committed State")
	}
	result, err = engine.Remove(ctx, link.ID)
	if err != nil || !result.Removed {
		t.Fatalf("public TLS exact owned removal: %+v %v", result, err)
	}
	if _, ok = mustLoadCrashSnapshot(t, store).Find(link.ID); ok {
		t.Fatal("public TLS original remained committed after verified removal")
	}
}
