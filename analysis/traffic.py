import pyshark
import collections

def analyze_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    dns_queries = set()
    http_requests = []
    protocol_counts = collections.Counter()

    for pkt in cap:
        protocol_counts[pkt.highest_layer] += 1

        # DNS queries
        if 'DNS' in pkt:
            try:
                if hasattr(pkt.dns, 'qry_name'):
                    dns_queries.add(pkt.dns.qry_name)
            except AttributeError:
                pass

        # HTTP requests
        if 'HTTP' in pkt:
            try:
                method = pkt.http.get('request_method', '')
                host = pkt.http.get('host', '')
                uri = pkt.http.get('request_uri', '')
                http_requests.append({'method': method, 'host': host, 'uri': uri})
            except AttributeError:
                pass

    cap.close()

    print("=== Protocol Statistics ===")
    for proto, count in protocol_counts.most_common():
        print(f"{proto}: {count}")

    print("\n=== DNS Queries ===")
    for domain in sorted(dns_queries):
        print(domain)

    print("\n=== HTTP Requests ===")
    for req in http_requests:
        print(f"{req['method']} {req['host']}{req['uri']}")

if __name__ == "__main__":
    analyze_pcap("path/to/your.pcap")