from scapy.all import IP, TCP, Raw, send

def send_syn_with_shadow(dest_ip, dest_port):
    # 1. Create the IP and TCP layers
    ip_layer = IP(dst=dest_ip)
    tcp_layer = TCP(
        sport=12345, # Source port
        dport=dest_port, # Destination port (e.g., 80)
        flags="S", # SYN flag
        seq=1000 # Starting sequence number
    )

    # 2. Create Raw payload with “[SHADOW]”
    payload = Raw(b"[SHADOW]echo TCP")

    # 3. Combine layers into a single packet
    packet = ip_layer / tcp_layer / payload

    # 4. Send the packet
    send(packet)

if __name__ == "__main__":
    send_syn_with_shadow("100.64.12.61",22)