# Basic Firewall 3-Host Docker Lab

This repository includes a single Docker Compose setup that builds a 3-host lab (two clients + firewall) using two internal Docker networks and a macvlan/host-LAN network.

## Topology

- **host1 (client1)**
  - `net10_1`: `10.1.0.2/24`
  - Default gateway: `10.1.0.1` (firewall)
- **host2 (client2)**
  - `net10_2`: `10.2.0.2/24`
  - Default gateway: `10.2.0.1` (firewall)
- **firewall (host3)**
  - `net10_1`: `10.1.0.1/24`
  - `net10_2`: `10.2.0.1/24`
  - `lan`: `192.168.1.70/24` via macvlan on `wlp131s0`
  - Default route: `192.168.1.2`

`net10_1` and `net10_2` are internal bridge networks. The firewall is attached to your LAN via `macvlan`.

## Usage

```bash
docker compose up --build
```

> If your LAN interface or IPs differ, update `docker-compose.yml` (the `lan` network `parent`, subnet, gateway, and the firewall's `ipv4_address`).

## Host ↔ Firewall macvlan access (if needed)

Some systems cannot reach macvlan containers directly from the host. If your host (`192.168.1.20`) cannot ping the firewall (`192.168.1.70`), create a host-side macvlan interface:

```bash
sudo ip link add macvlan0 link wlp131s0 type macvlan mode bridge
sudo ip addr add 192.168.1.71/24 dev macvlan0
sudo ip link set macvlan0 up
sudo ip route add 192.168.1.70/32 dev macvlan0
```

To remove it later:

```bash
sudo ip link delete macvlan0
```

## Firewall build + runtime details

- The firewall binary is built inside the image at `/opt/basic_firewall/build/Basic_Firewall`.
- The container runs the binary on startup.
- A simple HTTP server (`python3 -m http.server 80`) is started so `curl` checks can hit `10.1.0.1` and `10.2.0.1`.
- Configuration is mounted from `./resources/config.json` into `/opt/basic_firewall/resources/config.json`.
- TLS certificates are mounted from `./resources/certs` into `/opt/basic_firewall/resources/certs`.

## Acceptance test commands

```bash
# host1 -> firewall (ping + curl)
docker compose exec host1 ping -c 3 10.1.0.1
docker compose exec host1 curl -s http://10.1.0.1/

# host2 -> firewall (ping + curl)
docker compose exec host2 ping -c 3 10.2.0.1
docker compose exec host2 curl -s http://10.2.0.1/

# host1 -> host2 should be blocked by default
docker compose exec host1 ping -c 3 10.2.0.2

# outbound internet via firewall (NAT)
docker compose exec host1 curl -s https://ifconfig.me
docker compose exec host2 curl -s https://ifconfig.me

# firewall <-> host LAN connectivity
# (host side)
ping -c 3 192.168.1.70
# (firewall side)
docker compose exec firewall ping -c 3 192.168.1.20
```

## Notes

- `net10_1` and `net10_2` are isolated internal networks; there is no direct bridge to your LAN.
- Inter-subnet traffic (`10.1.0.0/24` ↔ `10.2.0.0/24`) is blocked by default. Update `resources/config.json` and/or the firewall rules if you want to allow it.
