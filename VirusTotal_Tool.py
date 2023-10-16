import argparse
import base64
import hashlib
import json
import multiprocessing
from configparser import ConfigParser
import pandas as pd
import pdfkit
import pathlib
import requests
import time
import os


class Color:
    re="\033[1;31m"
    gr="\033[1;32m"
    cy="\033[1;36m"
    yo="\033[1;33m"

class Configuration:
     # Reading Configs
    config = ConfigParser()
    config_path = pathlib.Path(__file__).parent.absolute() / "config.ini"
    config.read(config_path)
    
    'Telegram' in config
    VIRUS_TOTAL_API_KEY =  config['VirusTotal']['API_KEY']   #"57e3de8428a9e14885e553719f4800e738d2150b1058e51ee9b1dc0b9b0a044d"
    VIRUS_TOTAL_ENDPOINT_URL = config['VirusTotal']['ENDPOINT_URL'] #"https://www.virustotal.com/api/v3/urls/"
    VIRUS_TOTAL_REPORT_LINK = config['VirusTotal']['REPORT_LINK']  #"https://www.virustotal.com/gui/url/"
    TIME_STAMP = time.time()

class ipAnalysis():

    def __init__(self, islist = False):
        self.__islist = islist
    
    def urlReport(self, target_url):
        config = Configuration()
        color = Color()

        htmlTags = ""
        # os.system('clear')
        print(color.cy+"[+] Processing ", target_url + color.gr)
        # create virustotal "url identifier" from user input stored in target_url
        # Encode the user submitted url to base64 and strip the "==" from the end
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

        # amend the virustotal apiv3 url to include the unique generated url_id
        url = config.VIRUS_TOTAL_ENDPOINT_URL + url_id

        # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
        headers = {
            "Accept": "application/json",
            "x-apikey": config.VIRUS_TOTAL_API_KEY
        }
        try:
            response = requests.request("GET", url, headers=headers)

            # load returned json from virustotal into a python dictionary called decodedResponse
            decodedResponse = json.loads(response.text)
            htmlTags = self.formatingOutput(decodedResponse, target_url)
            return htmlTags
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "Error: " + target_url + " Reading Error, " +  error_msg
            print(msg)
            return msg

    def formatingOutput(self, decodedResponse, target_url):
        config = Configuration()
        # grab "last_analysis_date" key data to convert epoch timestamp to human readable date time formatted
        epoch_time = (decodedResponse["data"]["attributes"]["last_analysis_date"])
        # the original key last_analysis_date from the returned virustotal json will be removed and replaced with an updated last_analysis_date value that's now human readable
        time_formatted = time.strftime('%c', time.localtime(epoch_time))

        # create sha256 encoded vt "id" of each url or ip address to generate a hypertext link to a virustotal report in each table
        # create a string value of the complete url to be encoded
        UrlId_unEncrypted = ("http://" + target_url + "/")
        
        # encrypt and store our sha256 hashed hypertext string as
        sha_signature = self.encrypt_string(UrlId_unEncrypted)
    
        # create the hypertext link to the virustotal.com report
        vt_urlReportLink = (config.VIRUS_TOTAL_REPORT_LINK + sha_signature)

        # strip the "data" and "attribute" keys from the decodedResponse dictionary and only include the keys listed within "attributes" to create a more concise list stored in a new dictionary called a_json
        filteredResponse = (decodedResponse["data"]["attributes"])

        # create an array of keys to be removed from attributes to focus on specific content for quicker/higher-level analysis
        keys_to_remove = [
            "last_http_response_content_sha256", 
            "last_http_response_code",
            "last_http_response_content_length", 
            "url", 
            "last_analysis_date", 
            "tags", 
            "last_submission_date", 
            "threat_names",
            "last_http_response_headers",
            "categories",
            "last_modification_date",
            "title",
            "outgoing_links",
            "first_submission_date",
            "total_votes",
            "type",
            "id",
            "links",
            "trackers",
            "last_http_response_cookies",
            "html_meta"
            ]

        # iterate through the filteredResponse dictionary using the keys_to_remove array and pop to remove additional keys listed in the array
        for key in keys_to_remove:
            filteredResponse.pop(key, None)

        # create a dataframe with the remaining keys stored in the filteredResponse dictionary
        # orient="index" is necessary in order to list the index of attribute keys as rows and not as columns
        dataframe = pd.DataFrame.from_dict(filteredResponse, orient="index")
        
        dataframe.columns = [target_url]

        # grab "malicious" key data from last_analysis_stats to create the first part of the community_score_info
        community_score = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])

        # grab the sum of last_analysis_stats to create the total number of security vendors that reviewed the URL for the second half of the community_score_info
        total_vt_reviewers = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["harmless"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["suspicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["undetected"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["timeout"])

        # create a custom community score using community_score and the total_vt_reviewers values
        community_score_info = str(community_score)+ ("/") + str(total_vt_reviewers) + ("  :  security vendors flagged this as malicious")

        # amend dataframe with extra community score row
        dataframe.loc['Community Score',:] = community_score_info
        dataframe.loc['Last Analysis Date',:] = time_formatted
        dataframe.loc['VirusTotal_Report_Link',:] = vt_urlReportLink

        # change row labels name
        row_labels = {'last_analysis_stats':'Last Analysis Stats',
                    'reputation':'Reputation',
                    'times_submitted':'Times Submitted',
                    'last_final_url':'Last Final URL'
                    }

        dataframe.rename(index= row_labels, inplace=True)

        # sort dataframe index in alphabetical order to put the community score at the top
        dataframe.sort_index(inplace = True)

        #Details analysis report
        # change column labels
        col_labels = {'category': 'Category',
                    'result': 'Result',
                    'method': 'Method',
                    'engine_name': 'Engine Name'}

        dataframe =  dataframe.drop(['last_analysis_results'], axis="index")
        vt_analysis_result = pd.DataFrame.from_dict((decodedResponse["data"]["attributes"]["last_analysis_results"]), orient="index")
        vt_analysis_result.sort_values(by=['category'], ascending=False)
        vt_analysis_result.rename(columns= col_labels, inplace=True)

        # dataframe is output as an html table, and stored in the html variable
        html1 = dataframe.to_html(render_links=True, escape=False)
        html2 = vt_analysis_result.to_html(render_links=True, escape=False)
        htmlValue =  html1 + html2
        return htmlValue

    # begin function for encrypting our hyperlink string to sha256
    def encrypt_string(self, hash_string):
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    def urlHTML_Report(self, target_url):
        finalhtml = self.urlReport(target_url)
        HTMLReport = outputHTML(finalhtml)
        HTMLReport.outputHTML()

class ipList(object):
    
    def __init__(self, filename, progress_interval):
        self.__filename = filename
        self.__curr_iter = 0
        self.__prev_iter = 0
        self.__progress_interval = progress_interval
    
    def __readURLfile(self, q):
        color = Color()
        html = ""
        newhtml = ""
        ip_analysis = ipAnalysis()

        # self.start_reporting_progress()
        url_file = open(self.__filename, "r")
        for url in url_file.readlines():
            # self.__curr_iter += 1
            newhtml = ip_analysis.urlReport(url.strip())
            html = str(html) + str(newhtml)
        # self.stop_reporting_progress()
        print(color.cy+"[+] Finished Processing List"+color.gr)        
        
        HTMLReport = outputHTML(html)
        HTMLReport.outputHTML()

    @staticmethod
    def work(work_q, done_q):
        obj = work_q.get()
        obj.__readURLfile(done_q)

    # def start_reporting_progress(self):
    #     self.__progress_timer = threading.Timer(self.__progress_interval, self.start_reporting_progress)
    #     self.__progress_timer.start()
    #     print(f"iteration: {self.__curr_iter}, hashes/sec: {self.__curr_iter - self.__prev_iter}", flush=True)
    #     self.__prev_iter = self.__curr_iter

    # def stop_reporting_progress(self):
    #     self.__progress_timer.cancel()
    #     print(f"Finished set after {self.__curr_iter} iterations", flush=True)


class outputHTML:

    def __init__(self, html):
        self.__html = html
    
    def outputHTML(self):

        color = Color()    
        file_name_html  = "VirusTotalReport.html"
        file_name_pdf = "VirusTotalReport.pdf"
        
        # save html with css styled boilerplated code up to the first <body> tag to a variable named "header"
        header = """<!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Automated VirusTotal Analysis Report | API v3</title>
            <style>
                body {
                font-family: Sans-Serif;
                color: #1d262e;
                }
                h1 {
                    font-size: 1.25em;
                    margin: 50px 0 0 50px;
                }
                h2 {
                    font-size: .75em;
                    font-weight:normal;
                    margin: 5px 0 15px 50px;
                    color: #7d888b;
                }
                h3 {
                    font-size: 1em;
                    font-weight:normal;
                    margin: 0 0 20px 50px;
                    color: #7d888b;
                }
                h4 {
                    font-size: .750em;
                    font-weight:normal;
                    margin: 0 0 20px 50px;
                    text-align:right;
                    color: orange;
                }
                table {
                    text-align: left;
                    width: 100%;
                    border-collapse: collapse;
                    border: none;
                    padding: 0;
                    margin-left: 50px;
                    margin-bottom: 40px;
                    max-width: 1200px;
                }
                th { 
                    text-align: left;
                    border:none;
                    padding: 10px 0 5px 10px;
                    margin-left: 10px;
                }
                tr { 
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                    border-top: none;
                    border-left: none;
                    border-right: none;
                    padding-left: 10px;
                    margin-left: 0;
                }
                td { 
                    border-bottom: none;
                    border-top: none;
                    border-left: none;
                    border-right: none;
                    padding-left: 10px;
                }
                tr th {
                    padding: 10px 10px 5px 10px;
                }

            </style>
        </head>
        <body>
        <h1 class="reportHeader">VirusTotal Analysis Report</h1>
        <h2>VirusTotal API v3</h2>
        """
        # add report timestamp
        report_timestamp = str("<h3>" + time.strftime('%c', time.localtime(time.time())) + "</h3>")

        # save html closing </ body> and </ html> tags to a variable named "footer"
        # save html closing </ body> and </ html> tags to a variable named "footer"
        footer = """
             <script>
                const td_ele = document.querySelectorAll("td");
                function change_td_ele_color() {
                    for (let i = 0; i < td_ele.length; i++) { // iterate all thorugh td
                        if(td_ele[i].innerText.includes("malicious")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/malicious/g,'<span style="color:red">malicious</span>');                            
                        }
                        if(td_ele[i].innerText.includes("malware")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/malware/g,'<span style="color:red">malware</span>');                            
                        }
                        if(td_ele[i].innerText.includes("suspicious")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/suspicious/g,'<span style="color:orange">suspicious</span>');                            
                        }
                        if(td_ele[i].innerText.includes("undetected")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/undetected/g,'<span style="color:grey">undetected</span>');                            
                        }
                        if(td_ele[i].innerText.includes("unrated")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/unrated/g,'<span style="color:grey">unrated</span>');                
                        }
                        if(td_ele[i].innerText.includes("harmless")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/harmless/g,'<span style="color:green">harmless</span>');                            
                        }
                        if(td_ele[i].innerText.includes("clean")){
                            var ele = td_ele[i];
                            var html = ele.innerHTML;
                            td_ele[i].innerHTML = html.replace(/clean/g,'<span style="color:green">clean</span>');                            
                        }
//                        
//                        if (td_ele[i].innerText == "malicious" || td_ele[i].innerText == "malware") {
//                            td_ele[i].style.color = "red"; 
//                        }
//                        if(td_ele[i].innerText == "suspicious"){
//                            td_ele[i].style.color = "orange";
//                        }
//                        if(td_ele[i].innerText == "undetected" || td_ele[i].innerText == "unrated"){
//                            td_ele[i].style.color = "grey";
//                        }
//                        if(td_ele[i].innerText == "harmless" || td_ele[i].innerText == "clean"){
//                            td_ele[i].style.color = "green";
//                        }
                        
                    }
                }        
                change_td_ele_color();
            </script>
            <h2>Developed by: Alien.C00de 2023 ver:1.0.0</h2>
            <h4>--Alien.C00de--</h4>
            </body>
            </html>
        """
        # create and open the new VirusTotalReport.html file
        text_file = open(file_name_html, "w")
        text_file.write(header)
        text_file.close()

        # open and append VirusTotalReport.html with the human-readable date time stored in the report_timestamp variable
        text_file = open(file_name_html, "a") # append mode
        text_file.write(report_timestamp)
        text_file.close()

        # open and append VirusTotalReport.html with a single html table from urlReport(), or as an array of html tables returned by urlReportLst or urlReportIPLst
        text_file = open(file_name_html, "a") # append mode
        # iterate through the html array and write all the html tables to VirusTotalReport.html
        for x in self.__html:
            text_file.write(x)
        text_file.close()

        # open and append VirusTotalReport.html with the closing tags stored in the footer variable
        text_file = open(file_name_html, "a") # append mode
        text_file.write(footer)
        text_file.close()

        print(color.yo+"\n[+] HTML Report File", {file_name_html}, "Is Ready On\n", os.getcwd(), "\n")

        #Create pdf file from HTML file
        options = {
            'page-size': 'A4',
            'margin-top': '0.30in',
            'margin-right': '0.60in',
            'margin-bottom': '0.30in',
            'margin-left': '0.60in',
            'footer-right': '[page]',
            'encoding': "UTF-8",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ]
        }
        pdfkit.from_file(file_name_html, file_name_pdf, options=options)
        print(f"[+] PDF Report File", {file_name_pdf}, "Is Ready On\n", os.getcwd(), "\n")        

def VirusTotal_Main():
    # Parser to take the arguments
    parser = argparse.ArgumentParser(description="Python Tool: Generating Report From VirusTotal API's for IP & URL")
    parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
    parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
    # parser.add_argument("-u", "--url-list", help="bulk url analysis")
    parser.add_argument("-V", "--version", help="show program version", action="store_true")
    args = parser.parse_args()

    # Check for --single-entry or -s
    os.system('clear')
    if args.single_entry:
        ipReport = ipAnalysis()
        ipReport.urlHTML_Report(args.single_entry.strip())
    elif args.ip_list:
        print(f"[+] Reading List of IP / URL From {args.ip_list.strip()} File", flush=True)
        processes = []
        work_queue = multiprocessing.Queue()
        done_queue = multiprocessing.Queue()
        progress_interval = 2
        ip_list = ipList(args.ip_list.strip(), progress_interval)
        start_time = time.time()
        p = multiprocessing.Process(target=ipList.work, args=(work_queue, done_queue))
        processes.append(p)
        work_queue.put(ip_list)
        p.start()
    # Check for --url-list or -u
    # elif args.url_list:
    #     # urlReportLst(args.url_list)
    #     # outputHTML()
    #     pass
    # # Check for --version or -V
    elif args.version:
        print("\nPython Tool: Generating Report From VirusTotal API's for IP & URL\nDeveloped by: Alien.C00de:1.0.0\n")
    # Print usage information if no arguments are provided
    else:
        # print("usage: VirusTotal_Tool.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u URL_LIST] [-V]")
        print("usage: VirusTotal_Tool.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-V]")

if __name__ == '__main__':
    VirusTotal_Main()