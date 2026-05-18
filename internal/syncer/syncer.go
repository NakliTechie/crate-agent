// SPDX-License-Identifier: AGPL-3.0-or-later
// Package syncer drives the bidirectional sync loop: filesystem events out,
// Sync-primitive events in, with echo suppression by event ID. Binds to
// fabric-sdk-go. Lands at M3 (upload) + M4 (download) + M5 (move/delete).
package syncer
