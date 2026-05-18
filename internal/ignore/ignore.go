// SPDX-License-Identifier: AGPL-3.0-or-later
// Package ignore filters filesystem events using built-in patterns
// (.DS_Store, Thumbs.db, ~$*, *.swp, .git/, node_modules/, …) plus the
// user's .crateignore (gitignore-style). Lands at M3.
package ignore
