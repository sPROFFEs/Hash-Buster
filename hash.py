#!/usr/bin/env python3

import re
import urllib3
import os
import requests
import argparse
import concurrent.futures
import websocket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
parser = argparse.ArgumentParser()
parser.add_argument('-s', help='hash', dest='hash')
parser.add_argument('-f', help='file containing hashes', dest='file')
parser.add_argument('-d', help='directory containing hashes', dest='dir')
parser.add_argument('-t', help='number of threads', dest='threads', type=int)
args = parser.parse_args()

#flag
found=0
hashv = ''

#Colors and shit like that
end = '\033[0m'
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
dgreen = '\033[32m'
yellow = '\033[93m'
back = '\033[7;91m'
run = '\033[97m[~]\033[0m'
que = '\033[94m[?]\033[0m'
bad = '\033[91m[-]\033[0m'
info = '\033[93m[!]\033[0m'
good = '\033[92m[+]\033[0m'

cwd = os.getcwd()
directory = args.dir
file = args.file
thread_count = args.threads or 4

if directory:
    if directory[-1] == '/':
        directory = directory[:-1]
def alpha(hashvalue, hashtype):
    cookies = {
        'ASP.NET_SessionId': 'be2jpjuviqbaa2mmq1w4h5ci',
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        '__EVENTTARGET': 'Button1',
        '__VIEWSTATE': '6fEUcEEj0b0eN1Obqeu4TSsOBdS0APqz...',
        'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
        'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
        'ctl00$ContentPlaceHolder1$Button1': 'decrypt',
    }

    response = requests.post('https://www.cmd5.org/', cookies=cookies, headers=headers, data=data)
    match = re.search(r'<span id="LabelAnswer"[^>]+?>(.+)</span>', response.text)
    if match:
        return match.group(1)
    return False

def send_message(ws, message):
    pattern = r'"value\\":\\([^,]+)'
    global found, hashv
    ws.send(message)
    response = ws.recv()
    response2 = ws.recv()
    match1 =  re.search(pattern,response)

    if match1:
        x = match1.end()-2
        found =1
        hashv = response[148:x]
        return response[148:x]
        
def beta(hashvalue, hashtype):
    url = "wss://md5hashing.net/sockjs/697/etstxji0/websocket"
    ws = websocket.create_connection(url)
    connect_message = r'["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]'
    send_message(ws, connect_message)
    
    # Use str.replace for the method message
    base_message = r'["{\"msg\":\"method\",\"method\":\"hash.get\",\"params\":[\"HASH_TYPE\",\"HASH_VALUE\"],\"id\":\"1\"}"]'
    method_message = base_message.replace("HASH_TYPE", hashtype).replace("HASH_VALUE", hashvalue)
    send_message(ws, method_message)
    ls = r'["{\"msg\":\"sub\",\"id\":\"AZnxL9tsZpE6XMTDB\",\"name\":\"meteor_autoupdate_clientVersions\",\"params\":[]}"]'
    send_message(ws, ls)
    if found:   
      return hashv
    else:
        return False
    
  

def gamma(hashvalue, hashtype):
    response = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
    if response:
        return response
    else:
        return False

def theta(hashvalue, hashtype):
    response = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6' % (hashvalue, hashtype)).text
    if len(response) != 0:
        return response
    else:
        return False

def delta(hashvalue, hashtype):
    """LeakLookup - Free hash database"""
    try:
        response = requests.get(f'https://leaklookup.com/api/search/{hashvalue}', timeout=10, verify=False)
        if response.status_code == 200:
            data = response.text.strip()
            if data and data != hashvalue and 'not found' not in data.lower():
                return data
    except:
        pass
    return False

def epsilon(hashvalue, hashtype):
    """OnlineHashCrack - Free community database"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f'https://www.onlinehashcrack.com/hash-identification.php?hash={hashvalue}', 
                              headers=headers, timeout=10, verify=False)
        if response.status_code == 200 and hashvalue not in response.text:
            # Parse response for cracked value
            import re
            match = re.search(r'Plaintext:\s*([^\s<]+)', response.text)
            if match:
                return match.group(1)
    except:
        pass
    return False

def zeta(hashvalue, hashtype):
    """MD5Online - Another free database"""
    try:
        response = requests.post('https://md5.gromweb.com/query', 
                               data={'hash': hashvalue, 'string': ''}, 
                               timeout=10, verify=False)
        if response.status_code == 200:
            text = response.text.strip()
            if text and text != hashvalue and len(text) < 100:
                return text
    except:
        pass
    return False

def iota(hashvalue, hashtype):
    """HashToolkit - Free database"""
    try:
        response = requests.get(f'https://hashtoolkit.com/reverse-hash/?hash={hashvalue}', timeout=10, verify=False)
        if response.status_code == 200:
            match = re.search(r'title="decrypted hash">(.*?)</span>', response.text)
            if match:
                return match.group(1)
    except:
        pass
    return False

print (f'''\\033[1;97m_  _ ____ ____ _  _    ___  _  _ ____ ___ ____ ____
|__| |__| [__  |__|    |__] |  | [__   |  |___ |__/
|  | |  | ___] |  |    |__] |__| ___]  |  |___ |  \\  {red}v4.0\\033[0m\\n''' )

#md5 = [gamma, alpha, beta, theta, delta]
md5 = [alpha, beta, gamma, theta, delta, epsilon, zeta, iota]
sha1 = [alpha, beta, theta, delta, epsilon, zeta, iota]
sha256 = [alpha, beta, theta, delta, epsilon, zeta, iota]
sha384 = [alpha, beta, theta, delta, epsilon, zeta, iota]
sha512 = [alpha, beta, theta, delta, epsilon, zeta, iota]

def crack(hashvalue):
    result = False
    if len(hashvalue) == 32:
        if not file:
            print ('%s Hash function : MD5' % info)
        for api in md5:
            try:
                r = api(hashvalue, 'md5')
                if r: return r
            except Exception: continue
            
        # Try NTLM if MD5 failed
        if not file:
            print ('%s Hash function : NTLM' % info)
        for api in md5:
            try:
                r = api(hashvalue, 'ntlm')
                if r: return r
            except Exception: continue
            
    elif len(hashvalue) == 40:
        if not file:
            print ('%s Hash function : SHA1' % info)
        for api in sha1:
            try:
                r = api(hashvalue, 'sha1')
                if r: return r
            except Exception: continue
            
        # Try MySQL if SHA1 failed
        if not file:
            print ('%s Hash function : MySQL' % info)
        for api in sha1:
            try:
                r = api(hashvalue, 'mysql')
                if r: return r
            except Exception: continue
            
    elif len(hashvalue) == 64:
        if not file:
            print ('%s Hash function : SHA-256' % info)
        for api in sha256:
            try:
                r = api(hashvalue, 'sha256')
                if r: return r
            except Exception: continue
    elif len(hashvalue) == 96:
        if not file:
            print ('%s Hash function : SHA-384' % info)
        for api in sha384:
            try:
                r = api(hashvalue, 'sha384')
                if r: return r
            except Exception: continue
    elif len(hashvalue) == 128:
        if not file:
            print ('%s Hash function : SHA-512' % info)
        for api in sha512:
            try:
                r = api(hashvalue, 'sha512')
                if r: return r
            except Exception: continue
    else:
        if not file:
            print ('%s This hash type is not supported.' % bad)
            quit()
        else:
            return False

result = {}

def threaded(hashvalue):
    resp = crack(hashvalue)
    if resp:
        print (hashvalue + ' : ' + resp)
        result[hashvalue] = resp

def grepper(directory):
    os.system('''grep -Pr "[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}" %s --exclude=*.{png,jpg,jpeg,mp3,mp4,zip,gz} |
        grep -Po "[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}" >> %s/%s.txt''' % (directory, cwd, directory.split('/')[-1]))
    print ('%s Results saved in %s.txt' % (info, directory.split('/')[-1]))

def miner(file):
    lines = []
    found = set()
    with open(file, 'r') as f:
        for line in f:
            lines.append(line.strip('\n'))
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        if matches:
            for match in matches:
                found.add(match)
    print ('%s Hashes found: %i' % (info, len(found)))
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
    futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        if i + 1 == len(found) or (i + 1) % thread_count == 0:
            print('%s Progress: %i/%i' % (info, i + 1, len(found)), end='\r')

def single(args):
    result = crack(args.hash)
    if result:
        print (good ,result)
    else:
        print ('%s Hash was not found in any database.' % bad)

if directory:
    try:
        grepper(directory)
    except KeyboardInterrupt:
        pass

elif file:
    try:
        miner(file)
    except KeyboardInterrupt:
        pass
    with open('cracked-%s' % file.split('/')[-1], 'w+') as f:
        for hashvalue, cracked in result.items():
            f.write(hashvalue + ':' + cracked + '\n')
    print ('%s Results saved in cracked-%s' % (info, file.split('/')[-1]))

elif args.hash:
    single(args)
