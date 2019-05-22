import requests
import re
import html2text
import json
import sys

process = sys.argv[1]

#For ProcessChecker
burp0_url = "http://processchecker.com:80/file/" + process
burp0_cookies = requests.session().cookies
burp0_headers = requests.session().headers
response1 = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)

if not response1.history:
    response1 = response1.content.decode('utf-8')
    h = html2text.HTML2Text()
    h.ignore_links = False

    response1 = h.handle(response1)
    response1 = re.escape(response1)
    response1 = response1.replace("\\", "")
    response1 = re.search(r'(?s)(?<=Process Detail)(.*)(?=Comments)', response1).group()
    response1 = ("Process Checker: \n Process Detail " + response1)
    print("######################################################")
    print("\033[1;34;40m" + response1)
    print("######################################################")

else:
    print("Process not in database of ProcessChecker")

########################################################################################################################

#For SystemExplorer
process1 = process.replace(".", "-")
burp1_url = "http://systemexplorer.net:80/file-database/file/" + process1
burp1_cookies = requests.session().cookies
burp1_headers = requests.session().headers
response2 = requests.get(burp1_url, headers=burp1_headers, cookies=burp1_cookies)

if response2.status_code == 200:
    response2 = response2.content.decode('utf-8')
    h = html2text.HTML2Text()
    h.ignore_links = False

    response2 = h.handle(response2)
    response2 = re.escape(response2)
    response2 = response2.replace("\\", "")
    response2 = re.search(r'(?s)(?<=What is the)(.*)(?=## Add Review)', response2).group()
    response2 = ("SystemExplorer: \n What is the " + response2)
    print("######################################################")
    print("\033[1;34;40m" + response2)
    print("######################################################")

else:
    print("Process not in database of SystemExplorer")

########################################################################################################################

#For FileNet
burp3_url = "https://www.file.net:443/process/" + process + ".html"
burp3_cookies = requests.session().cookies
burp3_headers = requests.session().headers
response3 = requests.get(burp3_url, headers=burp3_headers, cookies=burp3_cookies)

if response3.status_code == 200:
    response3 = response3.content.decode('utf-8')
    h = html2text.HTML2Text()
    h.ignore_links = False

    response3 = h.handle(response3)
    response3 = re.escape(response3)
    response3 = response3.replace("\\", "")
    response3 = re.search(r'(?s)(?<=What is)(.*)(?=Do you have additional information)', response3).group()
    response3 = ("FileNet: \n What is the " + response3)
    print("######################################################")
    print("\033[1;34;40m" + response3)
    print("######################################################")

else:
    print("Process not in database of FileNet")

########################################################################################################################

#For EchoTrail
burp2_url = "https://api.echotrail.io:443/v1/ui/insights/" + process
burp2_headers = requests.session().headers
response4 = requests.get(burp2_url, headers=burp2_headers)

not_found = '{"message": "EchoTrail has never observed %s execute in the wild"}' % process

if response4.status_code == 200 and response4.text == not_found:
    print("Process not in database of EchoTrail")

else:
    response4 = response4.content.decode('utf-8')
    response4 = json.loads(response4)
    paths = "Paths: " + str(response4['paths'])
    parents = "\nParents: " + str(response4['parents'])
    children ="\nChildren: " + str(response4['children'])
    grandparents ="\nGrandparents: " + str(response4['grandparents'])
    hashes ="\nHashes: " + str(response4['hashes'])
    network ="\nNetwork: " + str(response4['network'])
    rank ="\nRank: " + str(response4['rank'])
    host_prev ="\nHost_Prev: " + str(response4['host_prev'])
    eps ="\nEps: " + str(response4['eps'])
    description ="\nDescription: " + str(response4['description'])
    intel ="\nIntel: " + str(response4['intel'])

    response4 = paths+parents+children+grandparents+hashes+network+rank+host_prev+eps+description+intel
    response4 = response4.replace(r"[[", "[")
    response4 = response4.replace("'", "")
    print("######################################################")
    print("EchoTrail: \n" + "\033[1;34;40m" + response4)
    print("######################################################")

