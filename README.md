# Virus-Total
This Code Analyse suspicious domains, IPs and URLs to detect malware and other breaches and share the report in HTML & PDF format. 

VirusTotal python program with multiprocessing to handle multiple IP list.

Install following library to run the code.
1. pip install Pandas
2. pip install requests
3. pip install configparser
4. sudo apt-get install wkhtmltopdf  - Install wkhtmltopdf (for Debian/Ubuntu)
5. pip install pdfkit


Following are the command to run the code.
1. For Single ip search
   python VirusTotal_Tool.py -s 8.8.8.8    
   
2. For Single URL search 
   python VirusTotal_Tool.py -s google.com

3. For List of IP search from file
   python VirusTotal_Tool.py -i target_ip.txt

Files 

1. Python File - VirusTotal_Tool.py
2. conftg.ini - This file conain API key and URL link from virustotal.com, please get your API key to run the program. 
3. File contain sample list of IP for search - target_ip.txt
4. HTML report file (output file) - VirusTotalReport.html
5. PDF report file (output file) - VirusTotalReport.pdf
