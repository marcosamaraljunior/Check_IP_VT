import requests
import argparse
import sys

# Initiate the parser
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--apikey",
                    help="The VT API Key")
parser.add_argument("-f", "--iplistfile",
                    help="The IP List File")

args = parser.parse_args()


lista_ip = open(args.iplistfile, 'r')
lista_ip = lista_ip.readlines()

LIST_MALICIOUS = []


def check_malicious(ip):

    headers = {
        'x-apikey': args.apikey}

    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

    ip_info = response.json()

    try:
        malicious_count = ip_info['data']['attributes']['last_analysis_stats']['malicious']

        if malicious_count > 0:
            if malicious_count == 1:
                print(f"{ip} - Malicious({malicious_count} Engine)")
            else:
                print(f"{ip} - Malicious({malicious_count} Egines)")

            LIST_MALICIOUS.append(ip)
    except:
        print(response.text)
        pass


for ip in lista_ip:
    ip = ip.replace('\n', '').replace(' ', '')
    check_malicious(ip)
