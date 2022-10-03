#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
attack_path = os.getcwd()
filepath =attack_path+'/attack_log/log/'
date_string='20220603'
filename= date_string+'_attack_log.txt'
class write_log():
    # def __init__(self):
        # self.delete_old_log_file()
    def delete_old_log_file(self):
        os.system('rm -rf '+filepath+filename)
        print('old file log is rm')

    def write_log_txt(self, data):
        with open(filepath+filename,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()
