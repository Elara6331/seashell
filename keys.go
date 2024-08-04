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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// ensureHostKeys attempts to add any host ssh keys to the server.
// If no keys are found, it generates and saves a new ed25519 keypair.
func ensureHostKeys(sshdir string, srv *ssh.Server) error {
	err := addHostKeys(sshdir, srv)
	if err != nil {
		return err
	}

	if len(srv.HostSigners) == 0 {
		log.Warn("No valid host keys found. Generating new ed25519 keys...")
		err = generateAndSaveKeys(sshdir, srv)
		if err != nil {
			return err
		}
	}

	return nil
}

// generateAndSaveKeys generates a new ed25519 keypair and saves it
// in the ssh directory.
func generateAndSaveKeys(sshdir string, srv *ssh.Server) error {
	if err := os.MkdirAll(sshdir, 0o755); err != nil {
		return err
	}

	_, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sshkey, err := gossh.NewSignerFromSigner(privkey)
	if err != nil {
		return err
	}
	srv.AddHostKey(sshkey)

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	user, err := user.Current()
	if err != nil {
		return err
	}

	privpem, err := gossh.MarshalPrivateKey(privkey, user.Username+"@"+hostname)
	if err != nil {
		return err
	}

	privdata := pem.EncodeToMemory(privpem)
	pubdata := gossh.MarshalAuthorizedKey(sshkey.PublicKey())

	err = os.WriteFile(filepath.Join(sshdir, "id_ed25519"), privdata, 0o600)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(sshdir, "id_ed25519.pub"), pubdata, 0o644)
}

// addHostKeys recursively walks the ssh directory looking for valid keypairs
// and adds them to the server.
func addHostKeys(sshdir string, srv *ssh.Server) error {
	if err := os.MkdirAll(sshdir, 0o755); err != nil {
		return err
	}

	return filepath.WalkDir(sshdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) == ".pub" || !strings.HasPrefix(d.Name(), "id_") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		key, err := gossh.ParsePrivateKey(data)
		if err != nil {
			log.Warn(
				"Invalid private key",
				slog.String("path", path),
				slog.Any("error", err),
			)
			return nil
		}

		srv.AddHostKey(key)
		return nil
	})
}
