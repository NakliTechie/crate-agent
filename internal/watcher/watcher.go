// SPDX-License-Identifier: AGPL-3.0-or-later
// Package watcher wraps fsnotify with platform-appropriate debouncing.
// Lands at M3. macOS uses FSEvents; Linux uses inotify; Windows (v1.1) uses
// ReadDirectoryChangesW. All routed through fsnotify with a 250ms per-file
// coalescing window.
package watcher
