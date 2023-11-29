import subprocess
import sys
import xml.etree.ElementTree as ET
from scapy.all import sniff
from reportlab.pdfgen import canvas


def check_network_traffic():
    packets = sniff(filter="tcp", count=50)

    pdf_filename = "traffic_report.pdf"
    pdf = canvas.Canvas(pdf_filename)

    for idx, packet in enumerate(packets):
        pdf.drawString(
            100, 800 - idx * 15, f"Packet {idx + 1}: {packet.summary()}"
        )

    pdf.save()
    print(f"Traffic report saved to {pdf_filename}")


def check_open_ports(ip):
    p = subprocess.Popen(
        ["nmap", "-oX", "-", "-p-", ip], stdout=subprocess.PIPE
    )
    output, error = p.communicate()
    if output:
        parse_xml(output.decode())


def parse_xml(xml):
    tree = ET.ElementTree(ET.fromstring(xml))
    root = tree.getroot()
    for item in root.findall(".//host/ports/port"):
        port_id = item.get("portid")
        if port_id:
            print("Port:", port_id, "is open.")


if __name__ == "__main__":
    if "-cnet" in sys.argv:
        check_network_traffic()
    else:
        if len(sys.argv) == 1:
            print(
                "Please enter an IP address or add flag \n"
                + "-cnet to capture network traffic"
            )
            sys.exit(1)

        length = len(sys.argv)
        list_of_ips = []

        for i in range(1, length):
            list_of_ips.append(sys.argv[i])

        ip_address = str(sys.argv[1])

        for i in range(0, len(list_of_ips)):
            p = subprocess.Popen(
                ["nmap", "-sn", "-Pn", list_of_ips[i]], stdout=subprocess.PIPE
            )
            output, error = p.communicate()
            print(
                f"***** Running nmap -sn -Pn {list_of_ips[i]} *****\n", output
            )

        host_status = str(output).find("Host seems down!")

        if host_status == -1:
            for i in range(0, len(list_of_ips)):
                check_open_ports(list_of_ips[i])
        else:
            print("Host seems to be down!")
