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
	"io"
	"net"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/melbahja/goph"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/router"
	"go.elara.ws/seashell/internal/sshctx"
	gossh "golang.org/x/crypto/ssh"
)

// proxySettings represents settings for the proxy backend.
type proxySettings struct {
	Server      string     `cty:"server"`
	User        *string    `cty:"user"`
	PrivkeyPath *string    `cty:"privkey"`
	UserMap     *cty.Value `cty:"user_map"`
}

// Proxy is the proxy backend. It returns a handler that establishes a proxy
// session to a remote server based on the provided configuration.
func Proxy(route config.Route) router.Handler {
	return func(sess ssh.Session, arg string) error {
		user, _ := sshctx.GetUser(sess.Context())
		if !route.Permissions.IsAllowed(user, "*") {
			return router.ErrUnauthorized
		}

		var opts proxySettings
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

		auth := goph.Auth{
			gossh.PasswordCallback(requestPassword(opts, sess)),
		}

		if opts.PrivkeyPath != nil {
			data, err := os.ReadFile(*opts.PrivkeyPath)
			if err != nil {
				return err
			}

			pk, err := gossh.ParsePrivateKey(data)
			if err != nil {
				return err
			}

			auth = append(goph.Auth{gossh.PublicKeys(pk)}, auth...)
		}

		c, err := goph.New(*opts.User, opts.Server, auth)
		if err != nil {
			return err
		}

		knownHostHandler, err := goph.DefaultKnownHosts()
		if err != nil {
			return err
		}

		c.Config.Callback = func(host string, remote net.Addr, key gossh.PublicKey) error {
			println("hi")
			err = goph.AddKnownHost(host, remote, key, "")
			if err != nil {
				return err
			}
			return knownHostHandler(host, remote, key)
		}

		baseCmd := sess.Command()

		var userCmd string
		if len(baseCmd) > 0 {
			userCmd = baseCmd[0]
		}

		var userArgs []string
		if len(baseCmd) > 1 {
			userArgs = baseCmd[1:]
		}

		cmd, err := c.Command(userCmd, userArgs...)
		if err != nil {
			return err
		}

		err = cmd.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, nil)
		if err != nil {
			return err
		}
		go sshHandleResize(resizeCh, cmd)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		defer stdin.Close()

		go io.Copy(sess, stdout)
		go io.Copy(stdin, sess)

		if len(baseCmd) == 0 {
			err = cmd.Shell()
		} else {
			err = cmd.Start()
		}
		if err != nil {
			return err
		}

		return cmd.Wait()
	}
}

// requestPassword asks the client for the remote server's password
func requestPassword(opts proxySettings, sess ssh.Session) func() (secret string, err error) {
	return func() (secret string, err error) {
		_, err = fmt.Fprintf(sess.Stderr(), "Password for %s@%s: ", *opts.User, opts.Server)
		if err != nil {
			return "", err
		}
		pwd, err := readPassword(sess)
		sess.Write([]byte{'\n'})
		return strings.TrimSpace(pwd), err
	}
}

// nomadHandleResize resizes the remote SSH pseudo-tty whenever it
// receives a client resize event over SSH.
func sshHandleResize(resizeCh <-chan ssh.Window, cmd *goph.Cmd) {
	for newSize := range resizeCh {
		cmd.WindowChange(newSize.Height, newSize.Width)
	}
}

// readPassword reads a password from the SSH session, sending an asterisk
// for each character typed.
//
// It handles interrupts (Ctrl+C), EOF (Ctrl+D), and backspace.
// It returns what it read once it receives a carriage return or a newline.
func readPassword(sess ssh.Session) (string, error) {
	var out []byte

	for {
		buf := make([]byte, 1)
		_, err := sess.Read(buf)
		if err != nil {
			return "", err
		}

		switch buf[0] {
		case '\r', '\n':
			return string(out), nil
		case '\x7F':
			if len(out) != 0 {
				out = out[:len(out)-1]
				// Delete the last asterisk character
				sess.Write([]byte("\x08 \x08"))
			}
			continue
		case '\x03', '\x04':
			sess.Close()
			return "", errors.New("password entry canceled")
		default:
			// Give users some feedback that their password is being received
			sess.Write([]byte{'*'})
		}

		out = append(out, buf[0])
	}
}
