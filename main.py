import platform
if platform.system() != "Windows":  sys.exit()
import sys
import re
import uuid
import wmi
import requests
import subprocess
import urllib3
from ctypes import *
import os

w = wmi.WMI()

# anti-vm (virtualenv)
def get_prefix():
    return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix
if get_prefix() != sys.prefix:
    sys.exit()

# secure requests against http debugging or internet disablement
def request(url):
    if len(requests.utils.getproxies()) != 0:
        sys.exit()
    urllib3.disable_warnings()
    lul = requests.Session()
    lul.trust_env = False
    for k in list(os.environ.keys()):
        if k.lower().endswith('_proxy'):
            sys.exit()
    try:
        lul.get('https://www.google.com', proxies={"http": None, "https": None})
    except:
        sys.exit()
        
    return lul.get(url, proxies={"http": None, "https": None}, verify=False)

# anti debugger (winapi)
if windll.kernel32.IsDebuggerPresent():
    sys.exit()
elif windll.kernel32.CheckRemoteDebuggerPresent(windll.kernel32.GetCurrentProcess(), False) != 0:
    sys.exit()
    
# anti-vm (usb ports)
if len(w.Win32_PortConnector()) == 0:
    sys.exit()()

# anti-vm (mac address)
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
macs = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
if mac[:8] in macs:
  sys.exit()
  
# anti-vm (uuid)
uuid = w.Win32_ComputerSystemProduct()[0].UUID
uuids = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
if uuid in uuids:
  sys.exit()
    
# anti-vm (ip)
ip = request('https://api.ipify.org')
ips = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
if ip in ips:
  sys.exit()
  
# anti-vm (bio guid)
guids = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BIOS_Serial_List.txt')
for bio in w.Win32_BIOS():
  bio_ser = bio.SerialNumber
  if bio_ser in guids:
    sys.exit()
    
# anti-vm (motherboard)
boards = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Serial_List.txt')
for board in w.Win32_BaseBoard():
  board_ser = board.SerialNumber
  if board_ser in boards:
    sys.exit()
    
# anti-vm (serial)
serials = request('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/DiskDrive_Serial_List.txt')
for disk in w.Win32_DiskDrive():
  disk_ser = disk.SerialNumber
  if disk_ser in serials:
    sys.exit()

print(request('https://youtube.com').text)
input()
