package linux

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Actual kernel acceptance. Opt-in and require a freshly unshared mapped root
// namespace with ONLY lo; otherwise skip before the first host write.
func TestWSSOriginalAliasAtomicKernelCreationNetNS(t *testing.T) {
	if os.Getenv("STL_WSS_ORIGIN_NETNS") != "1" {
		t.Skip("requires isolated mapped fresh user/net namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("not mapped root")
	}
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(raw)), "0 ") {
		t.Fatal("no mapped user namespace")
	}
	all, err := net.Interfaces()
	if err != nil || len(all) != 1 || all[0].Name != "lo" {
		t.Fatal("fresh isolated empty netns required")
	}
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	nonce := "0123456789abcdef0123456789abcdef"
	tag, err := WSSOwnerTag(id, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const name = "stlwgaaa11"
	staging, err := WSSStagingName(id, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := CreateWSSWireGuardStaged(ctx, staging); err != nil {
		t.Fatalf("nonce-derived staging NEWLINK rejected: %v", err)
	}
	dev, err := net.InterfaceByName(staging)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := DeleteLinkByIndex(ctx, dev.Index); err != nil {
			t.Fatal(err)
		}
	}()
	raw, err = exec.Command("ip", "-details", "-json", "link", "show", "dev", staging).Output()
	if err != nil {
		t.Fatal(err)
	}
	var stageRows []struct {
		Alias   string `json:"ifalias"`
		IfIndex int    `json:"ifindex"`
		IfName  string `json:"ifname"`
	}
	if err := json.Unmarshal(raw, &stageRows); err != nil || len(stageRows) != 1 || stageRows[0].Alias != "" ||
		stageRows[0].IfName != staging || stageRows[0].IfIndex != dev.Index {
		t.Fatalf("WSS initial kernel object lost its random creation name: %s", raw)
	}
	if err := CreateWSSWireGuardStaged(ctx, staging); err == nil {
		t.Fatal("exclusive creation accepted an occupied original staging identity")
	}
	if err := SetLinkAliasByIndex(ctx, dev.Index, tag); err != nil {
		t.Fatal(err)
	}
	if err := RenameLinkByIndex(ctx, dev.Index, name); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ip", "-details", "-json", "link", "show", "dev", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Alias   string `json:"ifalias"`
		IfIndex int    `json:"ifindex"`
		IfName  string `json:"ifname"`
	}
	if err := json.Unmarshal(out, &rows); err != nil || len(rows) != 1 || rows[0].Alias != tag ||
		rows[0].IfIndex != dev.Index || rows[0].IfName != name {
		t.Fatalf("atomic original alias missing or changed: kernel-json=%s rows=%+v expected=%s ifindex=%d", string(out), rows, tag, dev.Index)
	}
	parsed, original, ok := ParseWSSOwnerTag(rows[0].Alias)
	if !ok || parsed != id || original != nonce {
		t.Fatal("original object identity readback failed")
	}
	again, err := net.InterfaceByName(name)
	if err != nil || again.Index != dev.Index {
		t.Fatal("foreign same-name collision modified original interface")
	}
}
