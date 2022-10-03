#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# 啟動命令: sudo python3 test_modbus_tcp_clinet.py
from pyModbusTCP.client import ModbusClient
modbus_tcp_client = ModbusClient('192.168.3.13',502,auto_open=True) #UID 可能可以不用設
print(modbus_tcp_client.read_coils(0,100)) #讀取PLC線圈，從線圈(0) 開始 讀 100個
print(modbus_tcp_client.read_coils(8192,10))