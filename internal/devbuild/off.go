//go:build !dev

// Package devbuild tells whether the binary is a development build. Release
// builds (no tags) do not contain the dev login or the local Key Vault, so a
// configuration mistake cannot turn into an auth bypass (F6).
package devbuild

// Enabled is false in release builds.
const Enabled = false
