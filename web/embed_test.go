package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// TestEmbeddedAssetsExist: every /assets/ file that the embedded index.html
// loads is embedded too. With the committed placeholder (no UI built) it
// loads none; with a build it loads the build's. A built index.html
// committed without its assets made every v0.4.0 package serve a blank
// page (CHANGELOG 0.4.1).
func TestEmbeddedAssetsExist(t *testing.T) {
	index, err := fs.ReadFile(Dist, "dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"/(assets/[^"]+)"`).FindAllStringSubmatch(string(index), -1) {
		if _, err := fs.Stat(Dist, "dist/"+m[1]); err != nil {
			t.Errorf("index.html loads /%s, which is not embedded (%v)", m[1], err)
		}
	}
}
