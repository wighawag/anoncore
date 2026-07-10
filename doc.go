// Package anoncore is the module root for the shared, substrate-AGNOSTIC
// account/seed/marker/elevation core of the anon* family (anonctl, and the
// planned anonbox and anonseed). It defines no exported API of its own: the
// reusable packages live in subdirectories (account, provision, seedhome, marker,
// accountconfig, endpoint, sudoprobe, ui). This file exists so the module root is
// a buildable Go package, which lets the CI-gate pin (workflow_test.go) live at
// the repo root next to the files it reads.
//
// anoncore is a LIBRARY, not a binary: it ships no command and is imported by the
// tools that do. See README.md and docs/adr/ for the module boundary.
package anoncore
