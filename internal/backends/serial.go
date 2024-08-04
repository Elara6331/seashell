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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/zclconf/go-cty/cty/gocty"
	"go.bug.st/serial"
	"go.elara.ws/seashell/internal/config"
	"go.elara.ws/seashell/internal/router"
	"go.elara.ws/seashell/internal/sshctx"
)

// serialSettings represents settings for the serial backend.
type serialSettings struct {
	Directory     *string `cty:"directory"`
	File          *string `cty:"file"`
	Delimiter     *string `cty:"delimeter"`
	BaudRate      *int    `cty:"baud_rate"`
	Configuration *string `cty:"config"`
}

// Serial is the serial backend. It returns a handler that
// exposes a serial port on an SSH connection.
func Serial(route config.Route) router.Handler {
	return func(sess ssh.Session, arg string) error {
		user, _ := sshctx.GetUser(sess.Context())

		var opts serialSettings
		err := gocty.FromCtyValue(route.Settings, &opts)
		if err != nil {
			return err
		}

		if opts.Directory == nil && opts.File == nil {
			return errors.New("either directory or file must be set in the server config")
		}

		// Since we can't specify the size of a physical serial port,
		// we can discard the window size channel and the pty info.
		_, _, ok := sess.Pty()
		if !ok {
			return errors.New("this route only accepts pty sessions")
		}

		delimeter := valueOr(opts.Delimiter, ".")
		args := strings.Split(arg, delimeter)

		if len(args) == 0 {
			return errors.New("at least one argument required")
		}

		var file, baudRate, config string
		if opts.File != nil {
			file = *opts.File
			switch len(args) {
			case 1:
				baudRate = args[0]
			default:
				baudRate, config = args[0], args[1]
			}
		} else if opts.Directory != nil {
			switch len(args) {
			case 1:
				file = filepath.Join(*opts.Directory, args[0])
			case 2:
				file, baudRate = filepath.Join(*opts.Directory, args[0]), args[1]
			default:
				file, baudRate, config = filepath.Join(*opts.Directory, args[0]), args[1], args[2]
			}
		}
		
		if !route.Permissions.IsAllowed(user, filepath.Base(file)) {
			return router.ErrUnauthorized
		}

		mode, err := getSerialMode(opts, baudRate, config)
		if err != nil {
			return err
		}

		port, err := serial.Open(file, mode)
		if err != nil {
			return err
		}
		defer port.Close()

		go io.Copy(sess, port)
		io.Copy(port, sess)
		return nil
	}
}

// getSerialMode tries to get the serial mode configuration from the
// config or from the argument provided by the client.
func getSerialMode(opts serialSettings, baudRate, config string) (out *serial.Mode, err error) {
	if config == "" {
		if opts.Configuration == nil {
			return nil, errors.New("no serial configuration provided")
		}

		out, err = parseSerialMode(*opts.Configuration)
		if err != nil {
			return nil, err
		}
	} else {
		out, err = parseSerialMode(config)
		if err != nil {
			return nil, err
		}
	}

	if baudRate == "" {
		if opts.BaudRate == nil {
			return nil, errors.New("no baud rate provided")
		}

		out.BaudRate = *opts.BaudRate
	} else {
		out.BaudRate, err = strconv.Atoi(baudRate)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// parseSerialMode parses a serial mode string (e.x. 8n1)
func parseSerialMode(cfg string) (out *serial.Mode, err error) {
	cfg = strings.ToLower(cfg)

	out = &serial.Mode{}
	out.DataBits, err = strconv.Atoi(cfg[:1])
	if err != nil {
		return nil, err
	}

	switch parity := cfg[1]; parity {
	case 'n':
		out.Parity = serial.NoParity
	case 'e':
		out.Parity = serial.EvenParity
	case 'o':
		out.Parity = serial.OddParity
	case 'm':
		out.Parity = serial.MarkParity
	case 's':
		out.Parity = serial.SpaceParity
	default:
		return nil, fmt.Errorf("unknown parity mode: %c", parity)
	}

	switch stop := cfg[2:]; stop {
	case "1":
		out.StopBits = serial.OneStopBit
	case "1.5":
		out.StopBits = serial.OnePointFiveStopBits
	case "2":
		out.StopBits = serial.TwoStopBits
	default:
		return nil, fmt.Errorf("unsupported stop bit amount: %s", stop)
	}

	return out, nil
}
