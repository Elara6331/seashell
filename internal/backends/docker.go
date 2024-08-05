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
	"context"
	"errors"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/gliderlabs/ssh"
	"github.com/moby/moby/client"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/router"
	"go.elara.ws/seashell/internal/sshctx"
)

// dockerSettings represents settings for the docker backend.
type dockerSettings struct {
	Command    *cty.Value `cty:"command"`
	Privileged *bool      `cty:"privileged"`
	User       *string    `cty:"user"`
	UserMap    *cty.Value `cty:"user_map"`
}

// Docker is the docker backend. It returns a handler that connects
// to a Docker container and executes commands via an SSH session.
func Docker(route config.Route) router.Handler {
	return func(sess ssh.Session, arg string) error {
		user, _ := sshctx.GetUser(sess.Context())
		if !route.Permissions.IsAllowed(user, arg) {
			return router.ErrUnauthorized
		}

		var opts dockerSettings
		err := gocty.FromCtyValue(route.Settings, &opts)
		if err != nil {
			return err
		}

		pty, resizeCh, ok := sess.Pty()
		if !ok {
			return errors.New("this route only accepts pty sessions (try adding the -t flag)")
		}
		
		if opts.User == nil {
			userMap := ctyObjToStringMap(opts.UserMap)
			user, _ := sshctx.GetUser(sess.Context())

			if muser, ok := userMap[user.Name]; ok {
				opts.User = &muser
			} else {
				opts.User = &user.Name
			}
		}

		c, err := client.NewClientWithOpts(
			client.WithHostFromEnv(),
			client.WithVersionFromEnv(),
			client.WithTLSClientConfigFromEnv(),
		)
		if err != nil {
			return err
		}

		cmd := sess.Command()
		if len(cmd) == 0 {
			cmd = ctyTupleToStrings(opts.Command)
			if len(cmd) == 0 {
				cmd = []string{"/bin/sh"}
			}
		}

		idr, err := c.ContainerExecCreate(sess.Context(), arg, container.ExecOptions{
			User:         *opts.User,
			Privileged:   opts.Privileged != nil && *opts.Privileged,
			Tty:          true,
			AttachStdin:  true,
			AttachStderr: true,
			AttachStdout: true,
			Env:          append(sess.Environ(), "TERM="+pty.Term),
			Cmd:          cmd,
		})
		if err != nil {
			return err
		}

		go dockerHandleResize(resizeCh, sess.Context(), c, idr.ID)

		hr, err := c.ContainerExecAttach(sess.Context(), idr.ID, container.ExecAttachOptions{Tty: true})
		if err != nil {
			return err
		}
		defer hr.Close()

		err = c.ContainerExecStart(sess.Context(), idr.ID, container.ExecStartOptions{Tty: true})
		if err != nil {
			return err
		}

		go io.Copy(hr.Conn, sess)
		io.Copy(sess, hr.Reader)

		return nil
	}
}

// dockerHandleResize resizes the Docker pseudo-tty whenever it receives
// a client resize event over SSH.
func dockerHandleResize(resizeCh <-chan ssh.Window, ctx context.Context, c *client.Client, execID string) {
	for newSize := range resizeCh {
		c.ContainerExecResize(ctx, execID, container.ResizeOptions{
			Height: uint(newSize.Height),
			Width:  uint(newSize.Width),
		})
	}
}
