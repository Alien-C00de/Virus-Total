# VirusTotal Analysis Tool - Using Python

The VirusTotal Analysis Tool is a sophisticated Python application designed to scrutinize suspicious domains, IPs, and URLs. It employs advanced detection algorithms to identify malware and other security threats, subsequently sharing the findings in both HTML and PDF report formats.

## Key Features

- Analyzes and identifies potential threats in domains, IPs, and URLs.
- Generates comprehensive reports in HTML and PDF formats.
- Utilizes multiprocessing for efficient handling of multiple IP lists.

## Installation

To set up the VirusTotal Analysis Tool, you need to install the following libraries:

```bash
pip install pandas
pip install requests
pip install configparser
sudo apt-get install wkhtmltopdf  # For Debian/Ubuntu systems
pip install pdfkit
```

## Usage
The tool can be operated using the following commands:
- To analyze a single IP:
   ```bash
   python VirusTotal_Tool.py -s 8.8.8.8
   ```
- To analyze a single URL:
   ```bash
   python VirusTotal_Tool.py -s google.com
   ```
- To analyze a list of IPs from a file:
   ```bash
   python VirusTotal_Tool.py -i target_ip.txt
   ```

## File Descriptions

- VirusTotal_Tool.py: The main Python script for the analysis tool.
- config.ini: Configuration file containing the API key and URL link from virustotal.com. Please obtain your API key to operate the program.
- target_ip.txt: A sample file containing a list of IPs for analysis.
- VirusTotalReport.html: The HTML format report generated after analysis.
- VirusTotalReport.pdf: The PDF format report generated after analysis.
