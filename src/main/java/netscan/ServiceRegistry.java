
package netscan;

import java.util.Map;

/**
 * Maps well-known port numbers to the service usually found there.
 * This is a guess based on convention (IANA assignments), not proof:
 * anything can listen on any port.
 */
public final class ServiceRegistry {

    private static final Map<Integer, String> SERVICES = Map.ofEntries(
            Map.entry(20, "FTP-Data"),
            Map.entry(21, "FTP"),
            Map.entry(22, "SSH"),
            Map.entry(23, "Telnet"),
            Map.entry(25, "SMTP"),
            Map.entry(53, "DNS"),
            Map.entry(67, "DHCP"),
            Map.entry(69, "TFTP"),
            Map.entry(80, "HTTP"),
            Map.entry(110, "POP3"),
            Map.entry(111, "RPCbind"),
            Map.entry(123, "NTP"),
            Map.entry(135, "MS-RPC"),
            Map.entry(137, "NetBIOS-NS"),
            Map.entry(139, "NetBIOS-SSN"),
            Map.entry(143, "IMAP"),
            Map.entry(161, "SNMP"),
            Map.entry(389, "LDAP"),
            Map.entry(443, "HTTPS"),
            Map.entry(445, "SMB"),
            Map.entry(465, "SMTPS"),
            Map.entry(514, "Syslog"),
            Map.entry(587, "SMTP-Submission"),
            Map.entry(631, "IPP (Printing)"),
            Map.entry(993, "IMAPS"),
            Map.entry(995, "POP3S"),
            Map.entry(1433, "MS-SQL"),
            Map.entry(1521, "Oracle DB"),
            Map.entry(1883, "MQTT"),
            Map.entry(2049, "NFS"),
            Map.entry(2375, "Docker API"),
            Map.entry(3000, "Dev Server"),
            Map.entry(3306, "MySQL"),
            Map.entry(3389, "RDP"),
            Map.entry(5000, "Dev Server / UPnP"),
            Map.entry(5432, "PostgreSQL"),
            Map.entry(5672, "AMQP"),
            Map.entry(5900, "VNC"),
            Map.entry(6379, "Redis"),
            Map.entry(8000, "HTTP-Alt"),
            Map.entry(8080, "HTTP-Proxy"),
            Map.entry(8443, "HTTPS-Alt"),
            Map.entry(8888, "HTTP-Alt"),
            Map.entry(9000, "HTTP-Alt"),
            Map.entry(9200, "Elasticsearch"),
            Map.entry(11211, "Memcached"),
            Map.entry(27017, "MongoDB")
    );

    /** Ports scanned by the "Common ports" preset. */
    public static final String COMMON_PORTS =
            "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017";

    private ServiceRegistry() {}

    public static String lookup(int port) {
        return SERVICES.getOrDefault(port, "Unknown");
    }
}
