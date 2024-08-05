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

package backends

import (
	"github.com/zclconf/go-cty/cty"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/router"
)

// Backend represents a seashell backend
type Backend func(config.Route) router.Handler

// backends contains all the available backends
var backends = map[string]Backend{
	"proxy":  Proxy,
	"nomad":  Nomad,
	"docker": Docker,
	"serial": Serial,
}

// Get returns a backend given its name
func Get(name string) Backend {
	return backends[name]
}

// ctyTupleToStrings converts a cty tuple type to a slice of strings
func ctyTupleToStrings(t *cty.Value) []string {
	if t == nil {
		return nil
	}

	i := 0
	out := make([]string, t.LengthInt())
	iter := t.ElementIterator()
	for iter.Next() {
		_, val := iter.Element()
		if val.Type() == cty.String {
			out[i] = val.AsString()
		} else {
			out[i] = val.GoString()
		}
		i++
	}
	return out
}

// ctyObjToStringMap convertys a cty object type to a map from strings to strings
func ctyObjToStringMap(o *cty.Value) map[string]string {
	if o == nil {
		return map[string]string{}
	}

	out := make(map[string]string, o.LengthInt())
	iter := o.ElementIterator()
	for iter.Next() {
		key, val := iter.Element()
		if key.Type() != cty.String || val.Type() != cty.String {
			continue
		}
		out[key.AsString()] = val.AsString()
	}
	return out
}

// valueOr returns the value that v points to
// or a default value if v is nil.
func valueOr[T any](v *T, or T) T {
	if v == nil {
		return or
	}
	return *v
}
