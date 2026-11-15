# NetScan – Java Network Port Scanner

A beginner-friendly TCP port scanner written in plain Java, with a web dashboard for running scans, viewing results and exporting them as CSV.

> **Only scan systems you own or have explicit permission to test.** Unauthorised port scanning can break acceptable-use policies or the law. `scanme.nmap.org` is a host whose owners allow light test scans.

## Features

| Objective | How NetScan meets it |
|---|---|
| Port detection | TCP connect scan with `java.net.Socket` — each port is reported as **Open**, **Closed** or **No response** |
| Service identification | ~50 well-known ports mapped to services (HTTP, HTTPS, FTP, SSH, MySQL, RDP…) in `ServiceRegistry.java` |
| Network understanding | Code comments and the dashboard explain the TCP handshake and what each status means |
| User-friendly interface | Responsive dark dashboard: presets, timeout slider, clickable summary cards that filter the table |
| Result analysis | Open / closed / no-response counts, per-port response time, filtering |
| Report generation | **Export CSV** button (generated server-side by `/api/scans/{id}.csv`) |
| Practical learning | No frameworks — just the JDK: sockets, thread pools, an HTTP server, JSON by hand |
| Security awareness | Consent checkbox, explanation of why open ports matter, safe limits |
| Cloud deployment | Dockerfile ready for Render's free tier (steps below) |

## Project structure

```
netscan/
├── src/main/java/netscan/
│   ├── NetScanServer.java    # HTTP server, API endpoints, rate limiting, safety checks
│   ├── PortScanner.java      # multithreaded TCP connect scanner + port-range parser
│   ├── ScanResult.java       # record: port, status, service, latency
│   └── ServiceRegistry.java  # port number -> likely service
├── src/main/resources/public/
│   ├── index.html            # dashboard
│   ├── style.css
│   └── app.js                # calls the API, renders results
├── build.sh                  # compiles to build/netscan.jar with javac + jar
└── Dockerfile                # for cloud deployment
```

## How the scan works

For each port, `PortScanner.probe()` calls `socket.connect(address, timeout)`:

- **connect succeeds** → the 3-way handshake (SYN → SYN/ACK → ACK) finished → **OPEN**
- **`ConnectException`** → the host replied with RST → **CLOSED**
- **`SocketTimeoutException`** → no reply in time, typically a firewall dropping packets → **FILTERED / No response**

Ports are probed in parallel by a 200-thread `ExecutorService`, so 1,024 ports take a few seconds instead of many minutes.

## Run locally

Requires **JDK 17 or newer** (21 recommended). On macOS: `brew install openjdk@21`; on Windows/Linux get it from [adoptium.net](https://adoptium.net).

```bash
./build.sh
java -jar build/netscan.jar
```

Open http://localhost:8080 and scan `127.0.0.1` to see which ports your own machine has open. Use `PORT=9090 java -jar build/netscan.jar` to change the port.

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan` | Form fields: `host`, `ports` (`common`, `1-1024`, or e.g. `22,80,8000-8100`), `timeout` (100–3000 ms), `authorized=true` |
| `GET` | `/api/scans/{id}.csv` | Download a finished scan as CSV |
| `GET` | `/api/whoami` | Your IP as the server sees it |
| `GET` | `/api/config` | Limits and whether public mode is on |

## Safety limits

- Max **1,024 ports** per scan, one host per scan.
- One concurrent scan per client IP, and **5 scans per minute** in public mode (30 when running locally).
- The user must tick the authorisation checkbox (enforced by the server, not only the page).
- **Public mode** (on automatically in the Docker image and on Render/Railway, or set `NETSCAN_PUBLIC_MODE=true`) refuses loopback, private (10.x, 172.16–31.x, 192.168.x), link-local (incl. the cloud metadata address 169.254.169.254), CGNAT and reserved addresses. This stops a public deployment being used to probe the cloud provider's internal network. To scan your home network, run NetScan locally.

## Deploy free on Render

1. Push the `netscan` folder to a GitHub repository.
2. Sign in at [render.com](https://render.com) → **New** → **Web Service** → connect the repository.
3. Render detects the `Dockerfile`. Choose the **Free** instance type and click **Create Web Service**.
4. After the build finishes you get a public URL like `https://netscan-xxxx.onrender.com`.

Notes: free Render services sleep after ~15 minutes idle and take ~30–60 s to wake on the next visit. Some hosts block outbound connections to unusual ports, so results from the cloud may show more "No response" than a local scan.

Other free/low-cost options that accept the same Dockerfile: Railway, Fly.io, Koyeb.

## Ideas for extending it

- Banner grabbing: read the first line a service sends to confirm what it is.
- UDP scanning (`DatagramSocket`).
- Scan history page, or saving reports to a database.
- Live progress via Server-Sent Events.
