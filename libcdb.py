#!/usr/bin/python
#
# Simple script to query libcdb.com from command line
#

import requests
import bs4
import sys

def get_list(symb1, addr1, symb2, addr2):
    url = "http://libcdb.com/search?symbolA={:s}&addressA={:#x}&symbolB={:s}&addressB={:#x}"
    h = requests.get(url.format(symb1, addr1, symb2, addr2))
    if h.status_code != 200:
        print("HTTP request failed: code {:d} - {:s}".format(h.status_code, h.reason) )
        sys.exit(0)

    soup = bs4.BeautifulSoup(h.text, "lxml")
    res = soup.find(class_="search_results")
    results = []
    for link in res.find_all("a"):
        idx = link["href"].replace("/libc/","")
        idx = int(idx)
        results.append( (link.string, idx) )
    return results


def get_infos(idx):
    url = "http://libcdb.com/libc/{:d}".format(idx)
    h = requests.get(url)
    if h.status_code != 200:
        print("HTTP request failed: code {:d} - {:s}".format(h.status_code, h.reason) )
        sys.exit(0)
    soup = bs4.BeautifulSoup(h.text, "lxml")
    res = soup.find(class_="search")
    infos = {}

    # get link
    l = res.find("a")["href"]
    infos["link"] = "http://libcdb.com{:s}".format(l)

    # get interesting symbols
    symbols = {}
    for s in ["__libc_system", "execve", "__dup2", "__open", "__read", "__write"]:
        syms = get_symbols(idx, s)
        if len(syms):
            symbols[s] = syms
    infos["symbols"] = symbols

    return infos


def get_symbols(idx, symb):
    url = "http://libcdb.com/libc/{:d}/symbols?name={:s}".format(idx, symb)
    h = requests.get(url)
    if h.status_code != 200:
        print("HTTP request failed: code {:d} - {:s}".format(h.status_code, h.reason) )
        return []

    soup = bs4.BeautifulSoup(h.text, "lxml")
    res = soup.find("div", class_="search_results")
    results = []
    for dt in res.find_all("dt"):
        key = dt.string.strip()
        value = dt.next_sibling.next_sibling.string.strip()
        if len(key) and key==symb and len(value):
            results.append( (key, value) )

    return results


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Syntax:\n\t{} Symbol1=0xAddr1 Symbol2=0xAddr2".format(sys.argv[0]))
        print("Example:\n\t{} __libc_start_main=0xb74a43e0 setsockopt=0xb757c7b0".format(sys.argv[0]))
        sys.exit(1)

    symb1, addr1 = sys.argv[1].split("=")
    addr1 = int(addr1, 16)
    symb2, addr2 = sys.argv[2].split("=")
    addr2 = int(addr2, 16)

    # print("[+] Querying libcdb.com for {:s}={:#x} and {:s}={:#x}".format(symb1, addr1, symb2, addr2))
    items = get_list(symb1, addr1, symb2, addr2)
    if len(items)==0:
        print("[-] No result")
        exit(0)

    print ("[+] {:d} results, getting symbol address".format(len(items)))
    for item in items:
        name, idx = item
        infos = get_infos(idx)
        print("[{}] {}".format(idx, name))
        print("\t * url: {}".format(infos["link"]))
        for sym in infos["symbols"].keys():
            for k,v in infos["symbols"][sym]:
                print("\t {} = {}".format(k,v))
