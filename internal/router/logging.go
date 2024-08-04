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
	"log/slog"
	"time"

	"github.com/gliderlabs/ssh"
	"go.elara.ws/seashell/internal/sshctx"
)

// Logging returns a middleware that logs incoming session details,
// and closed connections, as well as any error that may have caused
// the connection to close.
func Logging(log *slog.Logger) Middleware {
	return func(next Handler) Handler {
		return func(sess ssh.Session, arg string) error {
			user, _ := sshctx.GetUser(sess.Context())
			route := sess.Context().Value(routeKey{}).(route)

			log.Info(
				"Incoming user session",
				slog.String("user", user.Name),
				slog.String("route", route.name),
				slog.String("arg", arg),
				slog.String("addr", sess.RemoteAddr().String()),
			)

			start := time.Now()
			err := next(sess, arg)
			duration := time.Since(start)

			if err != nil {
				log.Error(
					"Connection closed",
					slog.String("user", user.Name),
					slog.String("route", route.name),
					slog.Duration("duration", duration),
					slog.String("addr", sess.RemoteAddr().String()),
					slog.Any("error", err),
				)
			} else {
				log.Info(
					"Connection closed",
					slog.String("user", user.Name),
					slog.String("route", route.name),
					slog.Duration("duration", duration),
				)
			}

			return err
		}
	}
}
