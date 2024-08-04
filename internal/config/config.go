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

package config

import (
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/zclconf/go-cty/cty"
)

// Config represents the main config structure.
type Config struct {
	Settings *Settings `hcl:"settings,block"`
	Routes   []Route   `hcl:"route,block"`
	Auth     Auth      `hcl:"auth,block"`
}

// Settings represents settings for the SSH server.
type Settings struct {
	SSHDir     string `hcl:"ssh_dir,optional"`
	ListenAddr string `hcl:"listen_addr,optional"`
	Debug      bool   `hcl:"debug,optional"`
}

// Route represents a virtual host configuration.
type Route struct {
	Name        string         `hcl:"name,label"`
	Backend     string         `hcl:"backend"`
	Match       string         `hcl:"match"`
	Settings    cty.Value      `hcl:"settings"`
	Permissions PermissionsMap `hcl:"permissions,optional"`
}

// Auth contains the authentication settings.
type Auth struct {
	Fail2Ban *Fail2Ban `hcl:"fail2ban,block"`
	Users    []User    `hcl:"user,block"`
}

// Fail2Ban contains the fail2ban rate limiter settings.
type Fail2Ban struct {
	Limit    string `hcl:"limit"`
	Attempts int    `hcl:"attempts"`
}

// User contains the configuration for a virtual user.
type User struct {
	Name     string   `hcl:"name,label"`
	Password string   `hcl:"password,optional"`
	Groups   []string `hcl:"groups,optional"`
	Pubkeys  []string `hcl:"pubkeys,optional"`
}

// Load loads the configuration from the specified path.
func Load(path string) (cfg Config, err error) {
	err = hclsimple.DecodeFile(path, nil, &cfg)
	if cfg.Settings == nil {
		cfg.Settings = &Settings{}
	}
	return cfg, err
}
