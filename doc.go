// Package meshcore implements the MeshCore mesh protocol: packet
// encoding and decoding, node identities, path handling, routing
// types, deduplication rules, the text, group and admin payload
// codecs, node discovery, and Cayenne LPP sensor telemetry. It
// contains protocol primitives only — stateless codecs, no radio
// drivers, no transport, and no stateful application logic (a node's
// seen-packet cache, for one, belongs to the node, not here).
//
// This is an independent implementation. It is not affiliated with
// or endorsed by the MeshCore project.
//
// The canonical import path is meshrunner.dev/pkg/meshcore; the code
// is hosted at github.com/meshrunner-dev/meshcore-go.
package meshcore
