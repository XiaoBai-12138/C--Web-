# -*- coding:UTF-8 -*-
import re
import requests
import argparse
import threading
from socket import *

lock = threading.Lock()
OpenNum = 0
threads = []


def IP_List(ip):
    ips = len(ip.split('-'))
    iplist = []
    if ips == 1:  # 如果非多个IP则直接输出IP
        iplist.append(ip)
        return iplist
    else:
        ipx = ip.split('-')[0][:-len(ip.split('-')[0].split('.')[-1])]
        start = int(ip.split('-')[0].split('.')[-1])
        end = int(ip.split('-')[1]) + 1
        for i in range(start, end):
            iplist.append(ipx + str(i))
        return iplist


def Check(host, port, timeout):
    # with lock:
    try:
        global OpenNum
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        lock.acquire()
        OpenNum += 1
        print('[+] %s %d Open' % (host, port))
        lock.release()
        s.close()
    except:
        lock.acquire()
        # print('[-] %s %d Close' % (host, port))
        lock.release()
        pass


def Check_Web(ip, port, timeout):
    headers = {
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 '
                      'Safari/537.36',
        'Connection': 'close'
    }
    print('|IP                           |Code  |Server                  |Title')
    try:
        url = "http://" + str(ip) + ':' + str(port)
        r = requests.session().get(url=url, headers=headers, timeout=timeout)
        status = r.status_code
        if status != 500 and status != 500 and status != 501 and status != 502 and status != 503 and status != 504 and status != 505:
            title = re.search(r'<title>(.*)</title>', r.content.decode())
            if title:
                title = title.group(1).strip().strip("\r").strip("\n")
            else:
                title = 'None'
            banner = ''
            try:
                banner += r.headers['Server'][:21]
            except:
                pass
            print("|%-29s|%-6s|%-24s|%-35s" % (url, status, banner, title))
    except:
        pass


def main():
    print('''
__  __  ___      _       ___    ____       _      ___ 
\ \/ / |_ _|    / \     / _ \  | __ )     / \    |_ _|
 \  /   | |    / _ \   | | | | |  _ \    / _ \    | | 
 /  \   | |   / ___ \  | |_| | | |_) |  / ___ \   | | 
/_/\_\ |___| /_/   \_\  \___/  |____/  /_/   \_\ |___|

          ''')
    parser = argparse.ArgumentParser(description='IPC段/域名TCP扫描器')
    parser.add_argument('-i', help="设置IP范围1.1.1.1-255或域名地址", required=True)
    parser.add_argument('--port', help="指定端口范围1-65535，默认80", default=80)
    parser.add_argument('--web', help="是否进行Web扫描，默认：False", action='store_true', default=False)
    parser.add_argument('--timeout', help="设置超时时间，单位：S，默认：1S", default=1)
    args = parser.parse_args()
    i = args.i
    port = int(args.port)
    web = args.web
    timeout = args.timeout
    if web:
        print('|IP                           |Code  |Server                  |Title')
    else:
        print('[*] The Host:%s Scanning!' % i)
    IP = IP_List(i)
    for send in IP:
        if web:
            threads.append(threading.Thread(target=Check_Web, args=(send, port, timeout)))
        else:
            threads.append(threading.Thread(target=Check, args=(send, port, timeout)))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
    print('[*] A Total of %d Open Host ' % OpenNum)
