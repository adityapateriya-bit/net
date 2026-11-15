
package netscan;

/**
 * The outcome of probing a single TCP port.
 *
 * OPEN      - the TCP handshake completed, something is listening.
 * CLOSED    - the host answered with a reset (RST): reachable, but nothing listening.
 * FILTERED  - no answer before the timeout; usually a firewall silently dropping packets.
 */
public record ScanResult(int port, Status status, String service, long latencyMs) {

    public enum Status { OPEN, CLOSED, FILTERED }
}
