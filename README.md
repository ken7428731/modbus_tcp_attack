基於軟體定義網路技術之工業控制場域防護系統-滲透程式
=====
環境設定資訊(Environmental Setting Information):
===========
- Python3 Version: 3.8.1  
- OS Version: Ubuntu 20.04.4
- pyModbusTCP Version: 0.1.10
- python-nmap Version: 0.7.1
- python-nmap3 Version: 1.5.1
- git

情境: 可以將此程式安裝在[ryu](https://github.com/ken7428731/ryu.git)網路拓樸的Engineering workstation的設備上或其他Ubuntu設備上。

安裝步驟(Installation Steps):
===========
安裝 python3 (Version 3.8.1):  
    `sudo apt install python3-pip`  
安裝 pyModbusTCP (Version 0.1.10):  
    `sudo pip install pyModbusTCP`  
安裝 nmap3 ( version 1.5.1):  
    `sudo apt-get install nmap`  
    `sudo pip install python3-nmap`  
安裝 git :  
    `sudo apt-get install git`  
下載滲透程式:  
    `git clone https://github.com/ken7428731/modbus_tcp_attack.git`  

執行步驟(Execution Steps):
===========
先進到modbus_tcp_attack資料夾裡:  
    `cd modbus_tcp_attack`  
執行程式:  
    `sudo python3 auto_modbus_tcp_attack.py 192.168.3.0/24`  
如果要修改掃描範圍的話在到 auto_modbus_tcp_attack.py 程式裡的 #407行修改 掃描範圍  

其他設備環境設定(Other Devices Setting):
===========
可以參考此 [設定頁面](https://hackmd.io/@rrpSFv-qSLunmXT6FGkwBg/SksRTxVzo)  

參考(Reference)
=======
1. https://github.com/theralfbrown/smod-1.git
2. https://github.com/nmmapper/python3-nmap.git
3. Industrial Control Field Protection System Based on Software-defined Network Technology: https://hdl.handle.net/11296/3zh3g6