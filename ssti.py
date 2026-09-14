#!/usr/bin/env python3
# TBH-SSTI - Detector (Educational)
import requests, argparse, json, urllib.parse

BANNER = """\033[91m╔════════════════════════════════════╗
\033[91m║ \033[97mTBH-SSTI \033[91m- Detector               \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404 \033[91m║
\033[91m╚════════════════════════════════════╝\033[0m"""

PAYLOAD = "{{7*7}}"

def check(url):
    parsed=urllib.parse.urlparse(url)
    qs=urllib.parse.parse_qs(parsed.query)
    if not qs:
        test_url=f"{url}?q={urllib.parse.quote(PAYLOAD)}"
    else:
        k=list(qs.keys())[0]
        qs[k]=PAYLOAD
        test_url=urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)))
    try:
        r=requests.get(test_url,timeout=5,headers={'User-Agent':'TBH-SSTI/1.0'})
        vulnerable="49" in r.text  # 7*7=49
        return {"url":test_url,"status":r.status_code,"vulnerable":vulnerable}
    except: return {"url":test_url,"vulnerable":False}

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope yang diizinkan!\033[0m\n")
    parser=argparse.ArgumentParser(description="SSTI")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    args=parser.parse_args()
    print(f"[*] Testing {args.url} dengan payload: {PAYLOAD} -> 49")
    result=check(args.url)
    if result.get("vulnerable"): print(f"\033[91m[!] Potensi SSTI! {result['url']} -> {result['status']} contains 49\033[0m")
    else: print(f"\033[92m[✓] Tidak terdeteksi SSTI [{result.get('status')}]\033[0m")
    if args.json: open(args.json,'w').write(json.dumps(result,indent=2)); print(f"[✓] JSON: {args.json}")

if __name__=="__main__": main()
