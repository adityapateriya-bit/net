
package netscan;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class NetScanServer {

    private static final int MAX_STORED_SCANS = 50;
    private static final Pattern HOST_PATTERN =
            Pattern.compile("^[A-Za-z0-9.\\-:]{1,253}$");

    private final boolean publicMode;
    private final int scansPerMinute;
    private final PortScanner scanner = new PortScanner(200);

    private final Map<String, Deque<Long>> recentScansByClient =
            new ConcurrentHashMap<>();
    private final Set<String> clientsScanning =
            ConcurrentHashMap.newKeySet();

    private final Map<String, StoredScan> storedScans =
            Collections.synchronizedMap(
                    new LinkedHashMap<String, StoredScan>(16, 0.75f, false) {
                        @Override
                        protected boolean removeEldestEntry(
                                Map.Entry<String, StoredScan> eldest) {
                            return size() > MAX_STORED_SCANS;
                        }
                    });

    record StoredScan(String host, String ip, Instant startedAt,
                      long durationMs, List<ScanResult> results) {}

    public NetScanServer(boolean publicMode) {
        this.publicMode = publicMode;
        this.scansPerMinute = publicMode ? 5 : 30;
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(
                System.getenv().getOrDefault("PORT", "8080"));

        boolean publicMode =
                "true".equalsIgnoreCase(
                        System.getenv("NETSCAN_PUBLIC_MODE"))
                || System.getenv("RENDER") != null
                || System.getenv("RAILWAY_ENVIRONMENT") != null;

        new NetScanServer(publicMode).start(port);
    }

    public void start(int port) throws IOException {
        HttpServer server = HttpServer.create(
                new InetSocketAddress("0.0.0.0", port), 0);

        server.createContext("/api/config", this::handleConfig);
        server.createContext("/api/whoami", this::handleWhoami);
        server.createContext("/api/scan", this::handleScan);
        server.createContext("/api/scans/", this::handleCsv);
        server.createContext("/", this::handleStatic);

        server.setExecutor(Executors.newFixedThreadPool(16));
        server.start();

        System.out.println("NetScan running on http://localhost:" + port
                + (publicMode
                ? " (public mode: private targets blocked)" : ""));
    }

    private void handleConfig(HttpExchange ex) throws IOException {
        String json = "{\"publicMode\":" + publicMode
                + ",\"maxPorts\":" + PortScanner.MAX_PORTS_PER_SCAN
                + ",\"scansPerMinute\":" + scansPerMinute
                + ",\"commonPorts\":\"" + ServiceRegistry.COMMON_PORTS + "\"}";

        send(ex, 200, "application/json", json);
    }

    private void handleWhoami(HttpExchange ex) throws IOException {
        send(ex, 200, "application/json",
                "{\"ip\":\"" + json(clientIp(ex)) + "\"}");
    }

    private void handleScan(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Use POST.");
            return;
        }

        Map<String, String> form = parseForm(
                new String(ex.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8));

        if (!"true".equals(form.get("authorized"))) {
            sendError(ex, 400,
                    "Confirm that you own the target or have permission to scan it.");
            return;
        }

        String host = form.getOrDefault("host", "").trim();

        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        if (!HOST_PATTERN.matcher(host).matches()) {
            sendError(ex, 400, "Enter a valid hostname or IP address.");
            return;
        }

        List<Integer> ports;
        int timeout;

        try {
            ports = PortScanner.parsePorts(form.get("ports"));
            timeout = Integer.parseInt(
                    form.getOrDefault("timeout", "500"));

            if (timeout < 100 || timeout > 3000) {
                throw new IllegalArgumentException(
                        "Timeout must be 100-3000 ms.");
            }
        } catch (NumberFormatException e) {
            sendError(ex, 400, "Timeout must be a number.");
            return;
        } catch (IllegalArgumentException e) {
            sendError(ex, 400, e.getMessage());
            return;
        }

        InetAddress address;

        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            sendError(ex, 400, "Could not resolve '" + host + "'.");
            return;
        }

        if (publicMode && isPrivate(address)) {
            sendError(ex, 403,
                    "This public deployment cannot scan private, loopback or internal addresses ("
                    + address.getHostAddress()
                    + "). Run NetScan locally to scan your own network.");
            return;
        }

        String client = clientIp(ex);

        if (!allowScan(client)) {
            sendError(ex, 429,
                    "Rate limit: at most " + scansPerMinute
                    + " scans per minute and one at a time. Please wait a moment.");
            return;
        }

        try {
            Instant started = Instant.now();
            long t0 = System.currentTimeMillis();

            List<ScanResult> results =
                    scanner.scan(address, ports, timeout);

            long duration = System.currentTimeMillis() - t0;

            String id = UUID.randomUUID().toString();

            StoredScan scan = new StoredScan(
                    host, address.getHostAddress(),
                    started, duration, results);

            storedScans.put(id, scan);

            System.out.printf(
                    "Scan %s: %s (%s) %d ports in %d ms%n",
                    id, host, address.getHostAddress(),
                    ports.size(), duration);

            send(ex, 200, "application/json",
                    scanToJson(id, scan));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            sendError(ex, 500, "Scan interrupted.");
        } finally {
            clientsScanning.remove(client);
        }
    }

    private void handleCsv(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();

        String id = path.substring("/api/scans/".length())
                .replace(".csv", "");

        StoredScan scan = storedScans.get(id);

        if (scan == null) {
            sendError(ex, 404,
                    "Scan not found (results are kept for the last "
                    + MAX_STORED_SCANS + " scans).");
            return;
        }

        StringBuilder csv = new StringBuilder();

        csv.append("# NetScan report\n");
        csv.append("# Target,").append(csvCell(scan.host())).append('\n');
        csv.append("# IP,").append(scan.ip()).append('\n');
        csv.append("# Started (UTC),").append(scan.startedAt()).append('\n');
        csv.append("# Duration (ms),").append(scan.durationMs()).append('\n');
        csv.append("Port,Status,Service,Response Time (ms)\n");

        for (ScanResult r : scan.results()) {
            csv.append(r.port()).append(',')
                    .append(r.status()).append(',')
                    .append(csvCell(r.service())).append(',')
                    .append(r.latencyMs()).append('\n');
        }

        String filename = "netscan-"
                + scan.host().replaceAll("[^A-Za-z0-9.-]", "_")
                + ".csv";

        ex.getResponseHeaders().set(
                "Content-Disposition",
                "attachment; filename=\"" + filename + "\"");

        send(ex, 200, "text/csv; charset=utf-8", csv.toString());
    }

    private void handleStatic(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();

        if (path.equals("/")) {
            path = "/index.html";
        }

        if (path.contains("..")) {
            sendError(ex, 400, "Bad path.");
            return;
        }

        try (InputStream in =
                     NetScanServer.class.getResourceAsStream("/public" + path)) {

            if (in == null) {
                sendError(ex, 404, "Not found.");
                return;
            }

            send(ex, 200, contentType(path), in.readAllBytes());
        }
    }

    private boolean allowScan(String client) {
        if (!clientsScanning.add(client)) {
            return false;
        }

        Deque<Long> times =
                recentScansByClient.computeIfAbsent(
                        client, k -> new ArrayDeque<>());

        synchronized (times) {
            long now = System.currentTimeMillis();

            while (!times.isEmpty()
                    && now - times.peekFirst() > 60_000) {
                times.pollFirst();
            }

            if (times.size() >= scansPerMinute) {
                clientsScanning.remove(client);
                return false;
            }

            times.addLast(now);
        }

        return true;
    }

    static boolean isPrivate(InetAddress a) {
        if (a.isLoopbackAddress() || a.isSiteLocalAddress()
                || a.isLinkLocalAddress() || a.isAnyLocalAddress()
                || a.isMulticastAddress()) {
            return true;
        }

        byte[] b = a.getAddress();

        if (a instanceof Inet4Address) {
            int b0 = b[0] & 0xff;
            int b1 = b[1] & 0xff;

            return b0 == 0
                    || (b0 == 100 && b1 >= 64 && b1 < 128)
                    || (b0 == 192 && b1 == 0 && (b[2] & 0xff) == 0)
                    || (b0 == 198 && (b1 == 18 || b1 == 19))
                    || b0 >= 240;
        }

        if (a instanceof Inet6Address) {
            return (b[0] & 0xfe) == 0xfc;
        }

        return false;
    }

    private static String clientIp(HttpExchange ex) {
        String fwd = ex.getRequestHeaders()
                .getFirst("X-Forwarded-For");

        if (fwd != null && !fwd.isBlank()) {
            return fwd.split(",")[0].trim();
        }

        return ex.getRemoteAddress()
                .getAddress().getHostAddress();
    }

    private static String scanToJson(String id, StoredScan s) {
        int open = 0;
        int closed = 0;
        int filtered = 0;

        StringBuilder rows = new StringBuilder();

        for (ScanResult r : s.results()) {
            switch (r.status()) {
                case OPEN -> open++;
                case CLOSED -> closed++;
                case FILTERED -> filtered++;
            }

            if (rows.length() > 0) {
                rows.append(',');
            }

            rows.append("{\"port\":").append(r.port())
                    .append(",\"status\":\"").append(r.status()).append('"')
                    .append(",\"service\":\"").append(json(r.service())).append('"')
                    .append(",\"latencyMs\":").append(r.latencyMs())
                    .append('}');
        }

        return "{\"id\":\"" + id + "\""
                + ",\"host\":\"" + json(s.host()) + "\""
                + ",\"ip\":\"" + json(s.ip()) + "\""
                + ",\"startedAt\":\"" + s.startedAt() + "\""
                + ",\"durationMs\":" + s.durationMs()
                + ",\"summary\":{\"total\":" + s.results().size()
                + ",\"open\":" + open
                + ",\"closed\":" + closed
                + ",\"filtered\":" + filtered + "}"
                + ",\"results\":[" + rows + "]}";
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> map = new HashMap<>();

        for (String pair : body.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }

            String[] kv = pair.split("=", 2);

            String key = URLDecoder.decode(
                    kv[0], StandardCharsets.UTF_8);

            String val = kv.length > 1
                    ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8)
                    : "";

            map.put(key, val);
        }

        return map;
    }

    private static String json(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private static String csvCell(String s) {
        return (s.contains(",") || s.contains("\""))
                ? "\"" + s.replace("\"", "\"\"") + "\""
                : s;
    }

    private static String contentType(String path) {
        if (path.endsWith(".html")) return "text/html; charset=utf-8";
        if (path.endsWith(".css")) return "text/css; charset=utf-8";
        if (path.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (path.endsWith(".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }

    private static void sendError(
            HttpExchange ex, int code, String message) throws IOException {
        send(ex, code, "application/json",
                "{\"error\":\"" + json(message) + "\"}");
    }

    private static void send(
            HttpExchange ex, int code, String type, String body)
            throws IOException {
        send(ex, code, type,
                body.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(
            HttpExchange ex, int code, String type, byte[] body)
            throws IOException {

        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(code, body.length);

        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }
}
