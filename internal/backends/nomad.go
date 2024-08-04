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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/hashicorp/nomad/api"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/router"
	"go.elara.ws/seashell/internal/sshctx"
)

// nomadSettings represents settings for the nomad backend.
type nomadSettings struct {
	Server    string     `cty:"server"`
	Delimiter *string    `cty:"delimeter"`
	Region    *string    `cty:"region"`
	Namespace *string    `cty:"namespace"`
	AuthToken *string    `cty:"auth_token"`
	Command   *cty.Value `cty:"command"`
}

// Nomad is the nomad backend. It returns a handler that connects
// to a Nomad task and executes commands via an SSH session.
func Nomad(route config.Route) router.Handler {
	return func(sess ssh.Session, arg string) error {
		user, _ := sshctx.GetUser(sess.Context())

		var opts nomadSettings
		err := gocty.FromCtyValue(route.Settings, &opts)
		if err != nil {
			return err
		}

		_, resizeCh, ok := sess.Pty()
		if !ok {
			return errors.New("this route only accepts pty sessions (try adding the -t flag)")
		}

		c, err := api.NewClient(&api.Config{
			Address:   opts.Server,
			Region:    valueOr(opts.Region, ""),
			Namespace: valueOr(opts.Namespace, ""),
		})
		if err != nil {
			return err
		}

		delimeter := valueOr(opts.Delimiter, ".")
		args := strings.Split(arg, delimeter)

		allocList, _, err := c.Jobs().Allocations(args[0], false, nil)
		if err != nil {
			return err
		}

		if len(allocList) == 0 {
			return fmt.Errorf("job %q has no allocations", args[0])
		}

		cmd := sess.Command()
		if len(cmd) == 0 {
			cmd = ctyTupleToStrings(opts.Command)
			if len(cmd) == 0 {
				cmd = []string{"/bin/sh"}
			}
		}

		switch len(args) {
		case 1:
			alloc, _, err := c.Allocations().Info(allocList[0].ID, nil)
			if err != nil {
				return err
			}
			task := alloc.Job.TaskGroups[0].Tasks[0]

			if !route.Permissions.IsAllowed(
				user,
				"job:"+args[0],
				"task:"+task.Name,
				"group:"+valueOr(alloc.Job.TaskGroups[0].Name, "unknown"),
			) {
				return router.ErrUnauthorized
			}

			sizeCh := make(chan api.TerminalSize)
			go nomadHandleResize(resizeCh, sizeCh)
			_, err = c.Allocations().Exec(sess.Context(), alloc, task.Name, true, cmd, sess, sess, sess.Stderr(), sizeCh, nil)
			return err
		case 2:
			alloc, _, err := c.Allocations().Info(allocList[0].ID, nil)
			if err != nil {
				return err
			}
			group := alloc.Job.TaskGroups[0]
			for _, task := range group.Tasks {
				if task.Name != args[1] {
					continue
				}

				if !route.Permissions.IsAllowed(
					user,
					"job:"+args[0],
					"task:"+task.Name,
					"group:"+valueOr(group.Name, "unknown"),
				) {
					return router.ErrUnauthorized
				}

				sizeCh := make(chan api.TerminalSize)
				go nomadHandleResize(resizeCh, sizeCh)
				_, err = c.Allocations().Exec(sess.Context(), alloc, task.Name, true, cmd, sess, sess, sess.Stderr(), sizeCh, nil)
				return err
			}
			return errors.New("task not found")
		case 3:
			alloc, _, err := c.Allocations().Info(allocList[0].ID, nil)
			if err != nil {
				return err
			}

			group := alloc.Job.LookupTaskGroup(args[1])
			if group == nil {
				return errors.New("task group not found")
			}

			var taskName = args[2]
			if taskName == "" {
				taskName = group.Tasks[0].Name
			}

			if !route.Permissions.IsAllowed(
				user,
				"job:"+args[0],
				"task:"+taskName,
				"group:"+valueOr(group.Name, "unknown"),
			) {
				return router.ErrUnauthorized
			}

			sizeCh := make(chan api.TerminalSize)
			go nomadHandleResize(resizeCh, sizeCh)
			_, err = c.Allocations().Exec(sess.Context(), alloc, taskName, true, cmd, sess, sess, sess.Stderr(), sizeCh, nil)
			return err
		case 4:
			allocID := args[1]
			if index, err := strconv.Atoi(args[1]); err == nil && index < len(allocList) {
				allocID = allocList[index].ID
			}

			alloc, _, err := c.Allocations().Info(allocID, nil)
			if err != nil {
				return err
			}

			var group *api.TaskGroup
			if args[2] == "" {
				group = alloc.Job.TaskGroups[0]
			} else {
				group = alloc.Job.LookupTaskGroup(args[2])
				if group == nil {
					return errors.New("task group not found")
				}
			}

			var taskName = args[3]
			if taskName == "" {
				taskName = group.Tasks[0].Name
			}

			if !route.Permissions.IsAllowed(
				user,
				"job:"+args[0],
				"task:"+taskName,
				"group:"+valueOr(group.Name, "unknown"),
			) {
				return router.ErrUnauthorized
			}

			sizeCh := make(chan api.TerminalSize)
			go nomadHandleResize(resizeCh, sizeCh)
			_, err = c.Allocations().Exec(sess.Context(), alloc, taskName, true, cmd, sess, sess, sess.Stderr(), sizeCh, nil)
			return err
		}

		return nil
	}
}

// nomadHandleResize resizes the Nomad pseudo-tty whenever it receives
// a client resize event over SSH.
func nomadHandleResize(resizeCh <-chan ssh.Window, sizeCh chan<- api.TerminalSize) {
	defer close(sizeCh)
	for newSize := range resizeCh {
		sizeCh <- api.TerminalSize{
			Height: newSize.Height,
			Width:  newSize.Width,
		}
	}
}
