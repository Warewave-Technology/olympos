//go:build dev

package devbuild

// Enabled: this binary was built with -tags dev (lab, e2e and tests). Only
// such builds contain the dev login and the local Key Vault.
const Enabled = true
