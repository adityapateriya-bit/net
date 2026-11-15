
package netscan;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class PortScanner {

    public static final int MAX_PORTS_PER_SCAN = 1024;

    private final ExecutorService pool;

    public PortScanner(int threads) {
        this.pool = Executors.newFixedThreadPool(threads, r -> {
            Thread t = new Thread(r, "scanner");
            t.setDaemon(true);
            return t;
        });
    }

    public List<ScanResult> scan(InetAddress address, List<Integer> ports, int timeoutMs)
            throws InterruptedException {
        List<Callable<ScanResult>> tasks = new ArrayList<>();
        for (int port : ports) {
            tasks.add(() -> probe(address, port, timeoutMs));
        }

        List<ScanResult> results = new ArrayList<>();
        for (Future<ScanResult> f : pool.invokeAll(tasks)) {
            try {
                results.add(f.get());
            } catch (ExecutionException e) {
                // probe() handles its own exceptions
            }
        }
        results.sort(Comparator.comparingInt(ScanResult::port));
        return results;
    }

    static ScanResult probe(InetAddress address, int port, int timeoutMs) {
        long start = System.nanoTime();
        ScanResult.Status status;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), timeoutMs);
            status = ScanResult.Status.OPEN;
        } catch (ConnectException e) {
            status = ScanResult.Status.CLOSED;
        } catch (SocketTimeoutException | NoRouteToHostException e) {
            status = ScanResult.Status.FILTERED;
        } catch (IOException e) {
            status = ScanResult.Status.FILTERED;
        }
        long latency = (System.nanoTime() - start) / 1_000_000;
        return new ScanResult(port, status, ServiceRegistry.lookup(port), latency);
    }

    public static List<Integer> parsePorts(String spec) {
        if (spec == null || spec.isBlank()) {
            throw new IllegalArgumentException("Enter at least one port.");
        }
        if (spec.trim().equalsIgnoreCase("common")) {
            spec = ServiceRegistry.COMMON_PORTS;
        }
        TreeSet<Integer> ports = new TreeSet<>();
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            try {
                if (part.contains("-")) {
                    String[] range = part.split("-", 2);
                    int from = Integer.parseInt(range[0].trim());
                    int to = Integer.parseInt(range[1].trim());
                    if (from > to) {
                        int tmp = from;
                        from = to;
                        to = tmp;
                    }
                    checkPort(from);
                    checkPort(to);
                    if (to - from + 1 > MAX_PORTS_PER_SCAN) {
                        throw new IllegalArgumentException(tooMany());
                    }
                    for (int p = from; p <= to; p++) ports.add(p);
                } else {
                    int p = Integer.parseInt(part);
                    checkPort(p);
                    ports.add(p);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("'" + part + "' is not a valid port or range.");
            }
            if (ports.size() > MAX_PORTS_PER_SCAN) {
                throw new IllegalArgumentException(tooMany());
            }
        }
        if (ports.isEmpty()) {
            throw new IllegalArgumentException("Enter at least one port.");
        }
        return new ArrayList<>(ports);
    }

    private static void checkPort(int p) {
        if (p < 1 || p > 65535) {
            throw new IllegalArgumentException("Port " + p + " is out of range (1-65535).");
        }
    }

    private static String tooMany() {
        return "A single scan is limited to " + MAX_PORTS_PER_SCAN + " ports.";
    }
}
