import time
import requests
from collections import Counter

def vt_scan(url_test):
    '''
    Call VTScan
    :param url_test: url to scan
    :return: # positive engines, # total engines
    '''
    retry = 0
    api_key = "d665ea8a7c632253b0a18ede19d2d4bc1376e744710421c98d4d2b9df360cbe2"
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    params = {'apikey': api_key, 'resource': url_test, 'scan':1}
    response = requests.get(url, params=params)
    
    response = response.json()

    # This means the url wasnt in VT's database, preparing a new scan
    while("total" not in response and "positives" not in response and retry < 3):
        print("[*] " + str(retry) + " try. Maximum of 3 tries with 30 seconds interval...")
        # Intentionally sleeping for 30 seconds before coming back to retrieve results
        time.sleep(30)
        response = requests.get(url, params=params).json()
        retry +=1

    # Getting out of the loop means either tried >= 3 times, or successfully gotten result
    try:
        positive = response['positives']
        total = response['total']
        scans_result = response['scans']
        scans = []
        for item in scans_result.values():
            scans.append(item["result"])
        counter = Counter(scans)
        most_common = counter.most_common(1)[0][0]
    except KeyError:
        positive = None
        total = None
        most_common = "Undefined"

    return positive, total, most_common

