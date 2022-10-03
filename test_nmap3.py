#!/usr/bin/env python
# -*- coding:utf-8 -*-
# 啟動命令: sudo python3 test_nmap3.py
import nmap3
nmap = nmap3.Nmap()
os_results = nmap.nmap_os_detection("192.168.3.13") # 查看設備的相關資訊
print(os_results['192.168.3.13']['macaddress'])
nmap=nmap3.NmapHostDiscovery()
results = nmap.nmap_portscan_only('192.168.3.13/32') # 查詢 設備所開的服務
port_len=len(results['192.168.3.13']['ports'])
for i in range(port_len):
    print('Services_Port='+str(results['192.168.3.13']['ports'][i]['portid']))