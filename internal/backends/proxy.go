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
	"path"
	"strconv"
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
	Host        *string    `cty:"host"`
	Hosts       *cty.Value `cty:"hosts"`
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

		var matched bool
		var addr, portstr string
		if opts.Host == nil {
			hosts := ctyTupleToStrings(opts.Hosts)
			if len(hosts) == 0 {
				return errors.New("no host configuration provided")
			}
			
			for _, hostPattern := range hosts {
				addr, portstr, ok = strings.Cut(hostPattern, ":")
				if !ok {
					// addr is already set by the above statement, so just set the default port
					portstr = "22"
				}

				matched, err = path.Match(addr, arg)
				if err != nil {
					return err
				}

				if matched {
					addr = arg
					break
				}
			}
		} else {
			addr, portstr, ok = strings.Cut(*opts.Host, ":")
			if !ok {
				// addr is already set by the above statement, so just set the default port
				portstr = "22"
			}
		}

		if !matched {
			return errors.New("provided argument doesn't match any host patterns in configuration")
		}

		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return err
		}

		auth := goph.Auth{
			gossh.PasswordCallback(requestPassword(opts, sess, addr)),
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

		c, err := goph.NewConn(&goph.Config{
			Auth: auth,
			User: *opts.User,
			Addr: addr,
			Port: uint(port),
			Callback: func(host string, remote net.Addr, key gossh.PublicKey) error {
				found, err := goph.CheckKnownHost(host, remote, key, "")
				if !found {
					if err = goph.AddKnownHost(host, remote, key, ""); err != nil {
						return err
					}
				} else if err != nil {
					return err
				}
				return nil
			},
		})
		if err != nil {
			return err
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
func requestPassword(opts proxySettings, sess ssh.Session, addr string) func() (secret string, err error) {
	return func() (secret string, err error) {
		_, err = fmt.Fprintf(sess.Stderr(), "Password for %s@%s: ", *opts.User, addr)
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
