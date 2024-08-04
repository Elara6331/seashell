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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/gliderlabs/ssh"
	"go.elara.ws/loggers"
	"go.elara.ws/seashell/internal/backends"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/fail2ban"
	"go.elara.ws/seashell/internal/router"
	"golang.org/x/term"
)

var (
	handler = loggers.NewPretty(os.Stderr, loggers.Options{})
	log     = slog.New(handler)
)

func main() {
	genHash := flag.Bool("gen-hash", false, "Generate an argon2id hash")
	flag.Parse()

	if *genHash {
		fmt.Print("Password: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Error("Error reading password from terminal", slog.Any("error", err))
			os.Exit(1)
		}
		hash, err := argon2id.CreateHash(string(data), argon2id.DefaultParams)
		if err != nil {
			log.Error("Error calculating argon2id hash", slog.Any("error", err))
			os.Exit(1)
		}
		fmt.Printf("\n%s\n", hash)
		return
	}

	cfg, err := config.Load("seashell.hcl")
	if err != nil {
		log.Error("Error loading config file", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.Settings.Debug {
		handler.ShowCaller = true
		handler.Level = slog.LevelDebug
	}

	r := router.New()
	r.Use(router.Logging(log))

	for _, route := range cfg.Routes {
		backend := backends.Get(route.Backend)
		if backend == nil {
			log.Warn("Invalid backend", slog.String("id", route.Backend))
			continue
		}
		r.Handle(route.Name, route.Match, backend(route))
	}

	if cfg.Settings.ListenAddr == "" {
		cfg.Settings.ListenAddr = ":2222"
	}

	var f2b *fail2ban.Fail2Ban
	if cfg.Auth.Fail2Ban != nil {
		limit, err := time.ParseDuration(cfg.Auth.Fail2Ban.Limit)
		if err != nil {
			log.Error("Error parsing fail2ban limit", slog.Any("error", err))
		}
		f2b = fail2ban.New(limit, cfg.Auth.Fail2Ban.Attempts)
	}

	srv := &ssh.Server{
		Addr:                     cfg.Settings.ListenAddr,
		Handler:                  r.Handler,
		PublicKeyHandler:         pubkeyHandler(f2b, cfg),
		PasswordHandler:          passwordHandler(f2b, cfg),
		ConnectionFailedCallback: failedConnHandler(f2b),
	}

	if cfg.Settings.SSHDir == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Error("Error getting home directory", slog.Any("error", err))
			os.Exit(1)
		}
		cfg.Settings.SSHDir = filepath.Join(homedir, ".ssh")
	}

	err = ensureHostKeys(cfg.Settings.SSHDir, srv)
	if err != nil {
		log.Error("Error adding host keys", slog.Any("error", err))
		os.Exit(1)
	}

	log.Info("Starting seashell server", slog.String("addr", srv.Addr))

	if err := srv.ListenAndServe(); err != nil {
		log.Error("Error while running server", slog.Any("error", err))
	}
}
