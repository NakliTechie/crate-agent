// SPDX-License-Identifier: AGPL-3.0-or-later
// Package state owns the SQLite store (manifest_cache, sync_cursor,
// upload_queue). Schema in schema.sql; driver is modernc.org/sqlite to
// keep CGO_ENABLED=0. Lands at M3.
package state
