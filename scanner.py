
import nmap
import socket
import csv
import os
from datetime import datetime

# Initialize Nmap scanner
scanner = nmap.PortScanner()


def vulnerability_scanner(target):

    print("\n" + "=" * 55)
    print("          NETSHIELD VULNERABILITY SCANNER")
    print("=" * 55)

    # Validate target
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[ERROR] Invalid IP address or hostname!")
        return

    print("\nTarget IP:", ip)
    print("[INFO] Scanning started...\n")

    try:
        # Scan top 100 TCP ports and detect services
        scanner.scan(
            hosts=ip,
            arguments="-sT -sV --top-ports 100"
        )

    except Exception as error:
        print("[ERROR]", error)
        return

    if ip not in scanner.all_hosts():
        print("[ERROR] Target could not be scanned.")
        return

    ports_data = []
    findings = []

    print("-" * 75)
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE':<18}{'VERSION'}")
    print("-" * 75)

    for protocol in scanner[ip].all_protocols():

        ports = scanner[ip][protocol].keys()

        for port in sorted(ports):

            service_info = scanner[ip][protocol][port]

            service = service_info.get("name", "Unknown")
            product = service_info.get("product", "")
            version = service_info.get("version", "")
            state = service_info.get("state", "Unknown")

            details = f"{product} {version}".strip()

            print(
                f"{port:<10}{state:<12}"
                f"{service:<18}{details}"
            )

            ports_data.append([
                port, protocol, state,
                service, product, version
            ])

            # Basic exposure checks
            risky_ports = {
                21: "FTP service exposed",
                23: "Telnet service exposed",
                445: "SMB service exposed",
                3389: "Remote Desktop exposed",
                3306: "MySQL service exposed",
                5432: "PostgreSQL service exposed",
                6379: "Redis service exposed"
            }

            if port in risky_ports and state == "open":
                findings.append({
                    "port": port,
                    "service": service,
                    "risk": "Review",
                    "issue": risky_ports[port]
                })

    print("\n" + "=" * 55)
    print("           SECURITY ASSESSMENT")
    print("=" * 55)

    if findings:
        for item in findings:
            print(
                f"[REVIEW] Port {item['port']} - "
                f"{item['issue']}"
            )
    else:
        print("No predefined risky port exposures detected.")

    print("\n" + "=" * 55)
    print("               SCAN SUMMARY")
    print("=" * 55)

    print("Target IP       :", ip)
    print("Open Ports      :", sum(
        1 for row in ports_data if row[2] == "open"
    ))
    print("Potential Issues :", len(findings))
    print("Scan Time       :", datetime.now())

    # Generate CSV report
    os.makedirs("reports", exist_ok=True)

    filename = (
        "reports/scan_" +
        datetime.now().strftime("%Y%m%d_%H%M%S") +
        ".csv"
    )

    with open(filename, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Port", "Protocol", "State",
            "Service", "Product", "Version"
        ])

        writer.writerows(ports_data)

    print("\n[+] Report saved:", filename)
    print("=" * 55)


# Main program
if __name__ == "__main__":

    print("\nNETSHIELD - NETWORK VULNERABILITY SCANNER")

    print("\n1. Scan localhost")
    print("2. Scan authorized IP/hostname")

    choice = input("\nSelect option: ")

    if choice == "1":
        target = "127.0.0.1"

    elif choice == "2":
        target = input("Enter target IP/hostname: ").strip()

    else:
        print("Invalid option!")
        exit()

    if target:
        vulnerability_scanner(target)
    else:
        print("Target cannot be empty!")
