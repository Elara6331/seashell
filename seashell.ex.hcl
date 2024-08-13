settings {
    listen_addr = ":2222"
    debug = true
}

route "nomad" {
    backend = "nomad"
    match = "nomad\\.(.+)"
    settings = {
        server = "http://nomad:4646"
    }
    permissions = {
        admins = {
            allow = ["*"]
        }
    }
}

route "srv" {
    backend = "proxy"
    match = "srv"
    settings = {
        host = "1.2.3.4"
        privkey = "/home/elara/.ssh/id_ed25519"
    }
}

route "cluster" {
    backend = "proxy"
    match = "cluster\\.(.+)"
    settings = {
        hosts = ["node*", "nas", "192.168.1.*"]
        privkey = "/home/elara/.ssh/id_ed25519"
    }
}

route "docker" {
    backend = "docker"
    match = "docker\\.(.+)"
    settings = {
        command = ["/bin/bash"]
    }
}

route "serial" {
    backend = "serial"
    match = "serial\\.(.+)"
    settings = {
        directory = "/dev"
    }
}

auth {
    fail2ban {
        limit = "5m"
        attempts = 5
    }

    user "admin" {
        password = "$argon2id$v=19$m=65536,t=1,p=16$lFu9zVL125Ypnv+NK+6FgA$uEtZ7IRx7O3/xG9ViOkRBqJ3no9xMZT9VcoyY9cZqEU" # 1234
        groups = ["admins"]
        pubkeys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEEAxoKZPa16LYOXVAkjShGmxdDWeu/jW6BbhI76eUwX",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqaLNW3/uRoXi9GD1PQMVguLkv4SvO3pNDMZCnChcbR",
        ]
    }
}
