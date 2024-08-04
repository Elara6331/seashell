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

package sshctx

import (
	"context"

	"github.com/gliderlabs/ssh"
	"go.elara.ws/seashell/internal/config"
)

type (
	argCtxKey  struct{}
	userCtxKey struct{}
)

func SetArg(ctx ssh.Context, arg string)        { ctx.SetValue(argCtxKey{}, arg) }
func SetUser(ctx ssh.Context, user config.User) { ctx.SetValue(userCtxKey{}, user) }

func GetArg(ctx context.Context) (string, bool) {
	arg, ok := ctx.Value(argCtxKey{}).(string)
	return arg, ok
}

func GetUser(ctx context.Context) (config.User, bool) {
	user, ok := ctx.Value(userCtxKey{}).(config.User)
	return user, ok
}
