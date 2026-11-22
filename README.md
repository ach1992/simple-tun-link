# Simple Tun Link (STL)

**Connect two Linux servers through a private IP network.**

Simple Tun Link helps you create, manage and restore network tunnels without
manually configuring every interface and service. It has a guided terminal
menu, supports multiple independent tunnels on one server, and helps you
check whether traffic actually reaches the other side.

## What it supports

- **Direct tunnels:** GRE, IPIP and L2TPv3 (unencrypted).
- **Encrypted connections:** WireGuard, IPsec, WireGuard over WSS or QUIC,
  MASQUE CONNECT-IP, and Spoof Direct TUN.
- **Day-to-day management:** guided setup and import, connection checks,
  diagnostics, automatic restoration after reboot, and controlled removal.

The right connection method depends on your servers and network.
In particular, Spoof Direct TUN has passed isolated tests but **has not
been proven to work across all public ISPs and their source-IP filters**.
Read the [Spoof guide](docs/SPOOF-CARRIER.md) before using it.

## Quick start

You need two Linux servers you administer, **AMD64 or ARM64**, and
administrator (`sudo`) access. Install STL on **both**.

Download the complete guarded bootstrap from the
[latest official Stable release](https://github.com/ach1992/simple-tun-link/releases/latest)
and run it:

~~~bash
/usr/bin/env -i HOME=/ PATH=/usr/sbin:/usr/bin:/sbin:/bin TERM="${TERM-}" ${NO_COLOR+NO_COLOR=1} STL_NO_CLEAR="$([ "${STL_NO_CLEAR:-}" = 1 ] && printf 1)" /bin/bash -c 'set -eo pipefail; umask 077; f=$(/usr/bin/mktemp); trap '\''/bin/rm -f -- "$f"'\'' EXIT; /usr/bin/curl -q -fLSs --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 45 https://github.com/ach1992/simple-tun-link/releases/latest/download/stl-bootstrap.sh | /usr/bin/head -c 131073 > "$f"; [ -s "$f" ] && [ "$(/usr/bin/wc -c < "$f")" -le 131072 ] && /bin/bash -n "$f" && /bin/bash "$f" "$@"' stl
~~~

Then:

1. Open the guided menu with `sudo stl menu` on the first server.
2. Choose **Create tunnel** and the connection method you want.
3. Securely send its **Setup Link / Setup Code** to the second server.
4. On the second server choose **Import setup link**, then use
   **Test connectivity** on both servers.

Setup Links for encrypted methods may contain private credentials.
Send them only through a trusted channel.

## Installation, updates and help

The command above uses GitHub. If GitHub is inaccessible from your server,
you can install from a trusted HTTPS Mirror or transfer an official
single-file installer from another machine. Existing installations should
use **Update**, not repeat a new installation.

- [Install, Update and offline options](docs/INSTALL.md)
- [Menu and command reference](docs/CLI.md)
- [Diagnose or recover a connection](docs/DIAGNOSTICS.md)
- [All supported environments and requirements](docs/SUPPORTED-ENVIRONMENTS.md)
- Advanced carriers: [Spoof](docs/SPOOF-CARRIER.md) and [MASQUE](docs/MASQUE-CARRIER.md)
- [Project design](docs/PROJECT-SPEC.md), [security](docs/SECURITY.md) and [development](docs/DEVELOPMENT.md)

For more guides, browse [docs](docs/). See
[Releases](https://github.com/ach1992/simple-tun-link/releases)
for published versions and [Issues](https://github.com/ach1992/simple-tun-link/issues)
for remaining work.

## License

Copyright © 2026 ach1992. This source revision uses **GNU AGPLv3 only**
(`AGPL-3.0-only`). See [LICENSE](LICENSE) and
[third-party notices](THIRD-PARTY-NOTICES.txt).
Previously published `v0.1.34` and older releases remain under MIT.
