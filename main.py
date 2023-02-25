import platform
import sys
if platform.system() != "Windows":
    sys.exit()
import os
import wmi
import requests
import urllib3
import getmac
from ctypes import *

# requests seguros contra http debugging ou desativação de internet
def request(url: str) -> str:
    if len(requests.utils.getproxies()) != 0:
        sys.exit()
    urllib3.disable_warnings()
    lul = requests.Session()
    lul.trust_env = False
    for k in list(os.environ.keys()):
        if k.lower().endswith('_proxy'):
            sys.exit()
    try:
        lul.get('https://www.google.com', proxies={"http": None, "https": None}, verify=False)
    except:
        sys.exit()
        
    return lul.get(url, proxies={"http": None, "https": None}, verify=False).text

# anti debugger (winapi)
if windll.kernel32.IsDebuggerPresent():
    sys.exit()
elif windll.kernel32.CheckRemoteDebuggerPresent(windll.kernel32.GetCurrentProcess(), False) != 0:
    sys.exit()
    
# anti-vm (portas usb)
if len(wmi.WMI().Win32_PortConnector()) == 0:
    sys.exit()()

# anti-vm (endereço mac)
PREFIXOS = {'08:00:27', '00:05:69', '00:0C:29', '00:1C:14', '00:50:56', '00:1C:42', '00:16:3E', '0A:00:27'}
endereco_mac = getmac.get_mac_address()
if endereco_mac:
    prefixo = endereco_mac[:8].upper().replace('-', ':')
    if prefixo in PREFIXOS:
        sys.exit()
        
print(request('https://www.google.com'))
input()
