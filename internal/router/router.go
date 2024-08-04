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

package router

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/gliderlabs/ssh"
	"go.elara.ws/seashell/internal/sshctx"
)

// ErrUnauthorized represents an unauthorized access error.
var ErrUnauthorized = errors.New("you are not authorized to access this resource")

// Handler defines a function type to handle SSH sessions.
type Handler func(sess ssh.Session, arg string) error

// Middleware defines a function type for middleware.
type Middleware func(next Handler) Handler

// Router manages routing and middleware for SSH sessions.
type Router struct {
	routes      map[string]route
	middlewares []Middleware
}

// route represents a single route configuration.
type route struct {
	name    string
	handler Handler
	regex   *regexp.Regexp
}

// New creates and returns a new [Router] instance.
func New() *Router {
	return &Router{routes: map[string]route{}}
}

// Use adds a middleware to the router.
func (r *Router) Use(m Middleware) {
	r.middlewares = append(r.middlewares, m)
}

// Handle registers a new route with the given name and pattern.
func (r *Router) Handle(name, pattern string, h Handler) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.routes[pattern] = route{
		name:    name,
		handler: h,
		regex:   re,
	}
	return nil
}

// routeKey is a context key for storing route information.
type routeKey struct{}

// Handler handles an SSH session, routing it to the appropriate handler.
func (r *Router) Handler(sess ssh.Session) {
	arg, _ := sshctx.GetArg(sess.Context())

	for _, ro := range r.routes {
		matches := ro.regex.FindStringSubmatch(arg)
		if matches == nil {
			continue
		}

		sess.Context().SetValue(routeKey{}, ro)

		var cleanArg string
		if idx := ro.regex.SubexpIndex("arg"); idx != -1 {
			cleanArg = matches[idx]
		} else if len(matches) >= 2 {
			cleanArg = matches[1]
		} else {
			cleanArg = arg
		}

		handler := ro.handler
		for _, middleware := range r.middlewares {
			handler = middleware(handler)
		}

		err := handler(sess, cleanArg)
		if err != nil {
			writeError(sess, err.Error())
		}

		return
	}

	writeError(sess, "no matching route found for %q", arg)
}

// writeError writes a formatted error message to the SSH session.
func writeError(sess ssh.Session, format string, v ...any) {
	fmt.Fprintf(sess.Stderr(), "\x1b[31;1m[ERROR]\x1b[0m "+format+"\r\n", v...)
}
