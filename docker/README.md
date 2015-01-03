# Shadowsocks Dockerization

## How to use this image

Pull the image.

```bash
docker pull leesah/shadowsocks
```

Create a data container and edit the configuration file.

```bash
docker run --name shadowsocks-data leesah/shadowsocks /bin/true
docker run --rm --volumes-from shadowsocks-data leesah/shadowsocks vi /etc/shadowsocks.conf
```

Start the daemon container.

```bash
docker run --name shadowsocks-app --detach --publish 58388:8388 --volumes-from shadowsocks-data leesah/shadowsocks
```
