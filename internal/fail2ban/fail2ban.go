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

package fail2ban

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Fail2Ban represents a fail2ban-like rate limiter
type Fail2Ban struct {
	limit    time.Duration
	amount   int
	mtx      sync.Mutex
	attempts map[string]int
}

// New creates a new [Fail2Ban] instance.
func New(limit time.Duration, attempts int) *Fail2Ban {
	f := &Fail2Ban{
		limit:    limit,
		amount:   attempts,
		attempts: map[string]int{},
	}
	go f.clear()
	return f
}

// AddFailedLogin adds a failed login attempt from the given address.
func (f *Fail2Ban) AddFailedLogin(addr net.Addr) {
	if f == nil {
		return
	}

	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.attempts[getAddrString(addr)]++
}

// LoginAllowed checks if login is allowed from the given address.
func (f *Fail2Ban) LoginAllowed(addr net.Addr) bool {
	if f == nil {
		return true
	}

	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.attempts[getAddrString(addr)] < f.amount
}

// clear resets the login attempts at regular intervals.
func (f *Fail2Ban) clear() {
	for range time.Tick(f.limit) {
		f.mtx.Lock()
		clear(f.attempts)
		f.attempts = map[string]int{}
		f.mtx.Unlock()
	}
}

// getAddrString gets an IP address string from a [net.Addr].
func getAddrString(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP.String()
	case *net.IPAddr:
		return addr.IP.String()
	case *net.UDPAddr:
		return addr.IP.String()
	default:
		addrstr := addr.String()
		idx := strings.LastIndex(addrstr, ":")
		if idx == -1 {
			return addrstr
		}
		return addrstr[:idx]
	}
}
