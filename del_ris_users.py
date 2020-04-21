#!/usr/bin/python
# -*- encoding: UTF-8 -*-

import requests
import json
import urllib3
urllib3.disable_warnings()
import os
import logging
from logging.handlers import RotatingFileHandler

########################��Ҫ�޸ı��ݻ���ַ���½�һ��del_user_list.txt����Ҫɾ���û����б��嵥�ŵ�del_user_list.txt
opc_address = "10.2.170.70"
os_path = os.getcwd()+'\del_user_list.txt'

########################loggingģ�飬��ǰĿ¼����delete_user.log��־�ļ����鿴ɾ�����
LOG_FILE = 'delete_user.log'
DebugLevel = logging.DEBUG
logfilename = os.getcwd() + '\\' + LOG_FILE
print("��ǰ��־����·��Ϊ:"+logfilename)
logger = logging.getLogger()
Rotating_handler = RotatingFileHandler(logfilename, mode='a', maxBytes=1024*1024*5, backupCount=5, encoding=None, delay=0)
log_formatter = logging.Formatter('[%(asctime)s] [line:%(lineno)d] [%(levelname)s] %(message)s')
Rotating_handler.setFormatter(log_formatter)
logger.addHandler(Rotating_handler)
Rotating_handler.setLevel(DebugLevel)

########################���ݻ�API token��֤
class RISTOKEN():

    def get_auth_token(self):
        url = "https://"+opc_address+"/shterm/api/authenticate?"
        datas = {"username":self.username,"password":self.password}
        r = requests.post(url,datas,verify=False)
        if r.status_code == 200:
            token = r.json()['ST_AUTH_TOKEN']
            logger.warning('��ȡ st-auth-token �ɹ���')

        else:
            logger.warning('��ȡ st-auth-token ʧ�ܣ�')
        return token

    def __init__(self,username,password):
        self.username = username
        self.password = password

    def del_auth_token(self):
        headers = {'Content-Type': 'application/json;charset=UTF-8', 'st-auth-token': token}
        url = "https://"+opc_address+"/shterm/api/authenticate"
        r = requests.delete(url, headers=headers, verify=False)
        if r.status_code == 204:
            logger.warning('�ѳɹ�ע�� API token��')

##������Ҫ�޸�Ϊʵ�ʱ��ݻ�����Ա�˺ź�����
RisToken = RISTOKEN("admin","shterm")
token = RisToken.get_auth_token()

#��ȡdel_user_list.txt�ļ�����ȡ�û���ID
def get_user_id():
    headers = {'Content-Type': 'application/json;charset=UTF-8', 'st-auth-token': token}
    f = open(os_path,'r')
    ff = f.read().split("\n")
    DUser = {}
    for i  in range(len(ff)):
        url = "https://" + opc_address + "/shterm/api/user/" + "?loginName=" + str(ff[i])
        r = requests.get(url, headers=headers, verify=False)
        user_id_lists = r.json()
        userid = user_id_lists.get('content',None)
        if(0!=len(userid)):
            userid=userid[0]['id']
            DUser.update({ff[i]: userid})
    return DUser

#ɾ���û��Ľӿ�
def del_opc_user(idlist):
    for key, value in idlist.items():
        headers = {'Content-Type': 'application/json;charset=UTF-8', 'st-auth-token': token}
        url = "https://" + opc_address + "/shterm/api/user/" + str(value)
        r = requests.delete(url, headers=headers, verify=False)
        if r.status_code == 204:
            logger.warning("ɾ���û��ɹ�"+key)
        elif r.status_code == 410:
            logger.warning("�û���ɾ��")
        else:
            logger.warning("ɾ��"+key+"�û�ʧ��")
    return True

###����get_user_id��������ȡ���û�ID�嵥������idlist
idlist = get_user_id()
###��idlist(�û�id�嵥)����ɾ���û��Ľӿڣ�����ɾ���û�
del_opc_user(idlist)
###ע���û���token
RisToken.del_auth_token()
print("�������")


