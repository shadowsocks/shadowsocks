# Shadowsocks Dockerized

## What is Shadowsocks

A secure socks5 proxy designed to protect your Internet traffic.

See http://shadowsocks.org/

## What is Docker

An open platform for distributed applications for developers and sysadmins.

See https://www.docker.com/

## How to use this image

### Start the daemon for the firt time

Pull the image.

```bash
docker pull leesah/shadowsocks
```

Create a data container and edit the configuration file.

```bash
docker run --name shadowsocks-data leesah/shadowsocks /bin/true
docker run --interactive --tty --rm --volumes-from shadowsocks-data leesah/shadowsocks vi /etc/shadowsocks/shadowsocks.json
```

Start the daemon container.

```bash
docker run --name shadowsocks-app --detach --publish 58388:8388 --volumes-from shadowsocks-data leesah/shadowsocks
```

### Stop the daemon

```bash
docker stop shadowsocks-app
```

### Start a stopped daemon

```bash
docker start shadowsocks-app
```

### Upgrade

COMING SOON

### Use in CoreOS

COMING SOON

### Use with `fig`

COMING SOON

## References

[Shadowsocks - Servers](http://shadowsocks.org/en/download/servers.html)
