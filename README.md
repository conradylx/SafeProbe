![Scapy](https://img.shields.io/badge/Scapy-2_5_0)
![Nmap](https://img.shields.io/badge/Nmap-0)
# SafeProbe
SafeProbe is a Python script for analyzing network traffic and checking open ports on specified hosts using Scapy and Nmap.

## Features

- **Network Traffic Analysis:**
  - Captures network traffic using Scapy.
  - Generates a PDF report with information about captured packets.

- **Open Port Detection:**
  - Uses Nmap to scan for open ports on specified hosts.
  - Reports open ports in the console.

## Installation

1. Make sure you have Python installed on your system.
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
## Usage
Network Traffic Analysis

To capture network traffic and generate a report, run:
  ```bash
  python your_script_name.py -cnet
  ```
## Open Port Detection

To check open ports on specific hosts, run:

  ```bash
  python your_script_name.py <IP_Address1> <IP_Address2> ... <IP_AddressN>
  ```
Created for educational purposes. Work's still in progress.
