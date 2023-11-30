import subprocess
import sys
import xml.etree.ElementTree as ET

from reportlab.pdfgen import canvas
from scapy.all import sniff


def decorate_text(func):
    def wrapper(*args, **kwargs):
        ip_address = args[1]
        print(f"\n***** Running nmap for IP address: {ip_address} *****")
        func(*args, **kwargs)
        print("****************************************************")

    return wrapper


def check_network_traffic():
    """
    Check network traffic and generate a traffic report.

    This function uses the `sniff` function from the `scapy` library to capture network packets.
    It filters the packets to only include TCP packets and captures a maximum of 50 packets.
    It then generates a PDF report with the packet information using the `canvas` module from the `reportlab` library.
    The report includes the packet index and a summary of each packet.

    The generated PDF report is saved as "traffic_report.pdf" in the current directory.

    Example usage:
    >>> check_network_traffic()
    Traffic report saved to traffic_report.pdf
    """
    packets = sniff(filter="tcp", count=70)

    pdf_filename = "traffic_report.pdf"
    pdf = canvas.Canvas(pdf_filename)

    for idx, packet in enumerate(packets):
        pdf.drawString(
            100, 800 - idx * 15, f"Packet {idx + 1}: {packet.summary()}"
        )

    pdf.save()
    print(f"Traffic report saved to {pdf_filename}")


def check_open_ports(ip_address):
    """
    Check open ports for a given IP address.

    Parameters:
    ip_address (str): The IP address to check for open ports.

    Returns:
    None
    """
    with subprocess.Popen(
        ["nmap", "-oX", "-", ip_address], stdout=subprocess.PIPE
    ) as p:
        output, _ = p.communicate()
        if output:
            parse_xml(output.decode(), ip_address)


@decorate_text
def parse_xml(xml_data, ip_address):
    tree = ET.ElementTree(ET.fromstring(xml_data))
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

        list_of_ips = sys.argv[1:]

        for ip_address in list_of_ips:
            with subprocess.Popen(
                ["nmap", "-sn", "-Pn", ip_address], stdout=subprocess.PIPE
            ) as p:
                output, _ = p.communicate()
                print(
                    f"***** Running nmap -sn -Pn {ip_address} *****\n", output
                )
                host_status = str(output).find("Host seems down!")
                if host_status == -1:
                    check_open_ports(ip_address)
                else:
                    print("Host seems to be down!")
