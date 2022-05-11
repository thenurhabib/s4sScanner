#!/usr/bin/env python3
# coding=utf-8


import argparse
import random
import requests
import sys
from urllib import parse as urlparse

from plugins.banner import *
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# Print Banner
bannerFunc()

# Check if user enter arguments or not.
if len(sys.argv) <= 1:
    print(f"{bold}[~] No arguments, run {green}s4sscanner.py -h for help.{reset}")
    quit()


# User agents.
defaultUserAgent = {'User-Agent': 's4sscanner (https://github.com/thenurhabib/s4sscanner)','Accept': '*/*'}
timeout = 4

# Generate Random Strings
def generateRandomString(length=7):
    return ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(length))

# Arguments
parser = argparse.ArgumentParser(usage=f"{bold}{blue}S4SScanner Help Menu.{reset}{blue}")
parser.add_argument("-u", "--url",dest="url",help="Single URL",action='store')
parser.add_argument("-p", "--proxy",dest="proxy",help="Use proxy",action='store')
parser.add_argument("-l", "--list",dest="usedlist",help="URL List.",action='store')
parser.add_argument("--payload",dest="payloadFile",help="Use own payloads file",action='store',default="payload/payloads.txt")
parser.add_argument("--waf-bypass",dest="wafBypasspayloads",help="Detect WAF and bypass.",action='store_true')
parser.add_argument("--request-type",dest="requestType",help="Type of requests.",default="all",action='store')
parser.add_argument("--test-CVE-2022-22963",dest="testCVEFunc",help="Test for Spring Cloud RCE.",action='store_true')
args = parser.parse_args()
print(f"{reset}")



proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


# Function For Parse url.
def parseUniformResourceLocatorFunc(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = f"{str('http://')} {str(url)}"
    scheme = urlparse.urlparse(url).scheme
    pathofFile = urlparse.urlparse(url).path
    if (pathofFile == ''):
        pathofFile = '/'

    return({"scheme": scheme,"site": f"{scheme}://{urlparse.urlparse(url).netloc}",
    "host":  urlparse.urlparse(url).netloc.split(":")[0],"pathofFile": pathofFile})


def setUniformResourceLocatorPathFuc(url, path="/"):
    url_parsed = parseUniformResourceLocatorFunc(url)
    return f'{url_parsed["site"]}{path}'


def wafBypassPayloadUsingFunc():
    generateRandomString = generateRandomString()
    payloads = []
    with open(args.payloadFile, "r") as f:
        for payload in f.readlines():
            payload = payload.replace("{{random}}", generateRandomString)
            payloads.append(payload.strip())
    print(payloads)
    return payloads


def verifyBaseRequestsFunc(url, method):
    r = requests.request(url=url,method=method,
    headers=defaultUserAgent,verify=False,timeout=timeout,proxies=proxies)
    return r.status_code


def testUniformResourceLocatorCVE(url):
    mainPayloadVar = "class.module.classLoader[{{random}}]={{random}}"
    mainPayloadVar = mainPayloadVar.replace("{{random}}", generateRandomString())
    payloads = []
    payloads.append(mainPayloadVar)
    if args.wafBypasspayloads:
        payloads.extend(wafBypassPayloadUsingFunc())

    for payload in payloads:
        parameter, value = payload.split("=")
        print(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")

        if args.requestType.upper() in ("POST", "ALL"):
            try:
                requestVar = requests.request(url=url,method="POST",headers=defaultUserAgent,
                verify=False,timeout=timeout,data={parameter: value},proxies=proxies)
                if requestVar.status_code not in (200, 404) and verifyBaseRequestsFunc(url, "POST") != requestVar.status_code:
                    return True
            except Exception as error:
                print(f"Found an Error : {error}")
        if args.requestType.upper() in ("GET", "ALL"):
            try:
                r = requests.request(url=url,method="GET",headers=defaultUserAgent,verify=False,timeout=timeout,params={parameter: value},proxies=proxies)
                if r.status_code not in (200, 404) and verifyBaseRequestsFunc(url, "GET") != r.status_code:
                    return True
            except Exception as error:
                print(f"Found an Error : {error}")
    return False


def testCVEFunc(url):
    generateRandomString = generateRandomString()
    headers = {}
    headers.update(defaultUserAgent)
    url = setUniformResourceLocatorPathFuc(url, path="/functionRouter")
    print(f"[•] URL: {url}", "cyan")

    headers.update({"spring.cloud.function.routing-expression": generateRandomString})
    try:
        requestsVar = requests.request(url=url,method="POST",verify=False,timeout=timeout,
        data=generateRandomString,headers=headers,proxies=proxies)
        if requestsVar.status_code not in (200, 404) and verifyBaseRequestsFunc(url, "POST") != requestsVar.status_code:
            return True
    except Exception as error:
        print(f"Found an error : {error}")

    return False


def mainFunction():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as file:
            for x in file.readlines():
                x = x.strip()
                if x == "" or x.startswith("#"):
                    continue
                urls.append(x)

    vulnerableHosts = []
    for url in urls:
        print(f"{blue}[•] URL: {orange}{url}{reset}")
        print(f"{blue}Scaning Spring4Shell RCE (CVE-2022-22965.) vulnerablitry...{reset}")
        result = testUniformResourceLocatorCVE(url)
        if result:
            print(f"{bold}{red} [!] Domain Vulnerable. (CVE-2022-22965){reset}")
            vulnerableHosts.append(url)
        else:
            print(f"{green}[•] Website not vulnerable.{reset}")

        if args.testCVEFunc:
            print(f"{blue}[~] Checking for Spring Cloud RCE (CVE-2022-22963).{reset}")
            result = testCVEFunc(url)
            if result:
                print(f"{bold}{red} [!] Domain Vulnerable. (CVE-2022-22963){reset}")
                vulnerableHosts.append(url)
            else:
               print(f"{green}[•] Website not vulnerable.{reset}")

    if len(vulnerableHosts) == 0:
        print(f"{bold}{yellow}[•] No vulnerable websites found.{reset}")
    else:
        print(f"\n[!] Total Vulnerable Websites : {len(vulnerableHosts)}")
        for host in vulnerableHosts:
            print(f"[!] {host}")


if __name__ == "__main__":
    try:
        mainFunction()
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt Detected. Exiting...")
        quit()

