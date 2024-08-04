/*
 * Seashell - SSH server with virtual hosts and username-based routing
 *
 * Copyright (C) 2024 Elara6331 <elara@elara.ws>
 *
 * This file is part of Seashell.
 *
 * Seashell is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Seashell is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Seashell.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	"strings"
)

// PermissionsMap defines the config structure for permissions.
type PermissionsMap map[string]map[string][]string

// IsAllowed checks if the user has permissions for all the specified items.
// 
// The default policy is deny, and denials take priority, so if one item
// in items is set to deny, IsAllowed will always return false, even if
// other items are explicitly allowed.
func (pm PermissionsMap) IsAllowed(u User, items ...string) bool {
	if pm == nil {
		return true
	}

	for _, item := range items {
		allowed := false
		denied := false

		groups := append(u.Groups, "all")
		for _, group := range groups {
			perms, ok := pm[group]
			if !ok {
				continue
			}

			if denyList, found := perms["deny"]; found {
				for _, denyItem := range denyList {
					if matchPattern(denyItem, item) {
						denied = true
						break
					}
				}
			}

			if denied {
				break
			}

			if allowList, found := perms["allow"]; found {
				for _, allowItem := range allowList {
					if matchPattern(allowItem, item) {
						allowed = true
						break
					}
				}
			}
		}

		if denied || !allowed {
			return false
		}
	}
	return true
}

// matchPattern checks if an item matches a given pattern.
func matchPattern(pattern, item string) bool {
	if pattern == "*" {
		return true
	}
	if before, after, ok := strings.Cut(pattern, "*"); ok {
		return strings.HasPrefix(item, before) && strings.HasSuffix(item, after)
	}
	return pattern == item
}
