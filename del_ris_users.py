#!/usr/bin/python
# -*- encoding: UTF-8 -*-

import requests
import json
import urllib3
urllib3.disable_warnings()
import os
import logging
from logging.handlers import RotatingFileHandler

########################需要修改堡垒机地址，新建一个del_user_list.txt，将要删除用户的列表清单放到del_user_list.txt
opc_address = "10.2.170.70"
os_path = os.getcwd()+'\del_user_list.txt'

########################logging模块，当前目录生成delete_user.log日志文件，查看删除情况
LOG_FILE = 'delete_user.log'
DebugLevel = logging.DEBUG
logfilename = os.getcwd() + '\\' + LOG_FILE
print("当前日志绝对路径为:"+logfilename)
logger = logging.getLogger()
Rotating_handler = RotatingFileHandler(logfilename, mode='a', maxBytes=1024*1024*5, backupCount=5, encoding=None, delay=0)
log_formatter = logging.Formatter('[%(asctime)s] [line:%(lineno)d] [%(levelname)s] %(message)s')
Rotating_handler.setFormatter(log_formatter)
logger.addHandler(Rotating_handler)
Rotating_handler.setLevel(DebugLevel)

########################堡垒机API token认证
class RISTOKEN():

    def get_auth_token(self):
        url = "https://"+opc_address+"/shterm/api/authenticate?"
        datas = {"username":self.username,"password":self.password}
        r = requests.post(url,datas,verify=False)
        if r.status_code == 200:
            token = r.json()['ST_AUTH_TOKEN']
            logger.warning('获取 st-auth-token 成功！')

        else:
            logger.warning('获取 st-auth-token 失败！')
        return token

    def __init__(self,username,password):
        self.username = username
        self.password = password

    def del_auth_token(self):
        headers = {'Content-Type': 'application/json;charset=UTF-8', 'st-auth-token': token}
        url = "https://"+opc_address+"/shterm/api/authenticate"
        r = requests.delete(url, headers=headers, verify=False)
        if r.status_code == 204:
            logger.warning('已成功注销 API token！')

##这里需要修改为实际堡垒机管理员账号和密码
RisToken = RISTOKEN("admin","shterm")
token = RisToken.get_auth_token()

#读取del_user_list.txt文件，获取用户的ID
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

#删除用户的接口
def del_opc_user(idlist):
    for key, value in idlist.items():
        headers = {'Content-Type': 'application/json;charset=UTF-8', 'st-auth-token': token}
        url = "https://" + opc_address + "/shterm/api/user/" + str(value)
        r = requests.delete(url, headers=headers, verify=False)
        if r.status_code == 204:
            logger.warning("删除用户成功"+key)
        elif r.status_code == 410:
            logger.warning("用户已删除")
        else:
            logger.warning("删除"+key+"用户失败")
    return True

###调用get_user_id方法，获取到用户ID清单，存入idlist
idlist = get_user_id()
###将idlist(用户id清单)传入删除用户的接口，批量删除用户
del_opc_user(idlist)
###注销用户的token
RisToken.del_auth_token()
print("清理完成")


