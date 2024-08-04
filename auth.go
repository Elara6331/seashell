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

package main

import (
	"log/slog"
	"net"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/gliderlabs/ssh"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/fail2ban"
	"go.elara.ws/seashell/internal/sshctx"
)

// passwordHandler returns a handler that checks password authentication attempts against
// fail2ban and the configured argon2id password hash.
func passwordHandler(f2b *fail2ban.Fail2Ban, cfg config.Config) ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) (ok bool) {
		if !f2b.LoginAllowed(ctx.RemoteAddr()) {
			log.Warn(
				"Login attempt blocked by fail2ban policy",
				slog.String("username", ctx.User()),
				slog.String("addr", ctx.RemoteAddr().String()),
			)
			return false
		}

		user, ok := getUser(ctx, cfg)
		if !ok {
			return false
		}

		ok, err := argon2id.ComparePasswordAndHash(password, user.Password)
		return err == nil && ok
	}
}

// pubkeyHandler returns a handler that checks public key authentication attempts against
// fail2ban and the configures authorized public keys.
func pubkeyHandler(f2b *fail2ban.Fail2Ban, cfg config.Config) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) (ok bool) {
		if !f2b.LoginAllowed(ctx.RemoteAddr()) {
			log.Warn(
				"Login attempt blocked by fail2ban policy",
				slog.String("username", ctx.User()),
				slog.String("addr", ctx.RemoteAddr().String()),
			)
			return false
		}

		user, ok := getUser(ctx, cfg)
		if !ok {
			return false
		}

		for i, pubkeyStr := range user.Pubkeys {
			pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkeyStr))
			if err != nil {
				log.Warn("Invalid pubkey", slog.String("user", user.Name), slog.Int("index", i))
				continue
			}

			if ssh.KeysEqual(key, pubkey) {
				return true
			}
		}

		return false
	}
}

// failedConnHandler returns a handler that reports failed login attempts
// to the rate limiter.
func failedConnHandler(f2b *fail2ban.Fail2Ban) ssh.ConnectionFailedCallback {
	return func(conn net.Conn, err error) {
		if strings.Contains(err.Error(), "permission denied") {
			log.Warn("Failed login attempt", slog.Any("addr", conn.RemoteAddr()))
			f2b.AddFailedLogin(conn.RemoteAddr())
		}
	}
}

// getUser uses information from the request to retrieve the seashell user
// that is attempting to authenticate.
func getUser(ctx ssh.Context, cfg config.Config) (config.User, bool) {
	user, ok := sshctx.GetUser(ctx)
	if ok {
		return user, true
	} else {
		username, arg, ok := strings.Cut(ctx.User(), ":")
		if !ok {
			username, arg, ok = strings.Cut(ctx.User(), "~")
			if !ok {
				return config.User{}, false
			}
		}
		sshctx.SetArg(ctx, arg)

		for _, user := range cfg.Auth.Users {
			if user.Name == username {
				sshctx.SetUser(ctx, user)
				return user, true
			}
		}
	}
	return config.User{}, false
}
