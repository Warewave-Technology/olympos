package testutil

import "os"

// DockerSkipped reports whether OLYMPOS_SKIP_DOCKER=1 asks every test that
// needs Docker to skip, even with OLYMPOS_REQUIRE_DOCKER=1. CI sets it in the
// release-build job: the dev-build job runs the same Docker tests, and what
// differs between the builds (the dev login, the local key vault) is not in
// them.
func DockerSkipped() bool { return os.Getenv("OLYMPOS_SKIP_DOCKER") == "1" }
