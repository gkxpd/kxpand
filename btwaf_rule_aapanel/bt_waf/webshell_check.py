# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 x6
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2017 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: lkqiang<lkq@bt.cn>
# +-------------------------------------------------------------------
# +--------------------------------------------------------------------
# |   防火墙内部扫描webshell
# +--------------------------------------------------------------------
import sys
sys.path.append('/www/server/panel/class')
import json, os, time, public, string, re, hashlib,send_mail
os.chdir('/www/server/panel')
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class webshell_check:
    __webshell='/www/server/btwaf/webshell.json'
    __shell_check='/www/server/btwaf/shell_check.json'
    __check_path='/www/server/panel/plugin/btwaf/shell.json'
    __wubao = '/www/server/panel/plugin/btwaf/wubao.json'
    __mail = send_mail.send_mail()

    def ReadFile(self, filename, mode='r'):
        import os
        if not os.path.exists(filename): return False
        try:
            fp = open(filename, mode)
            f_body = fp.read()
            fp.close()
        except Exception as ex:
            if sys.version_info[0] != 2:
                try:
                    fp = open(filename, mode, encoding="utf-8")
                    f_body = fp.read()
                    fp.close()
                except Exception as ex2:
                    return False
            else:
                return False
        return f_body
    
    def is_open(self):
        try:
            result = json.loads(self.ReadFile('/www/server/btwaf/config.json'))
            if result['webshell_open']:return True
            else:return False
        except:
            return False
    def send_san_dir(self):
        if not self.is_open():
            exit('未开启webshell查杀')
        try:
            result = json.loads(self.ReadFile(self.__shell_check))
        except:
            result=[]
            public.WriteFile(self.__shell_check, json.dumps([]))
            os.system('/etc/init.d/nginx restart')
        if len(result)>500:
            result = []
            public.WriteFile(self.__shell_check, json.dumps([]))
            os.system('/etc/init.d/nginx restart')
        self.upload_shell(result)

    def is_data(self,data,i2):
        for i in data:
            if i2==i[0]:return True
        return False

    def is_white(self,path):
        if os.path.exists(self.__wubao):
            try:
                result = json.loads(self.ReadFile(self.__wubao))
                if path in result:return True
                return False
            except:
                return False

    def check_path(self,data):
        tem = int(time.time())
        if not os.path.exists(self.__check_path):
            public.WriteFile(self.__check_path, json.dumps({'time':tem,"data":[]}))
            return False
        try:
            result = json.loads(self.ReadFile(self.__check_path))
            if tem-result['time']>43200:
                result['time']=tem
                result['data']=[]
                public.WriteFile(self.__check_path, json.dumps(result))
                return False
            if not self.is_data(result['data'],data):
                result['data'].append([data,1])
                public.WriteFile(self.__check_path, json.dumps(result))
                return False
            for i in result['data']:
                if data==i[0]:
                    if i[1]>=2:
                        return True
                    else:
                        i[1]+=1
                        public.WriteFile(self.__check_path, json.dumps(result))
                        return False
        except:
            public.WriteFile(self.__check_path, json.dumps({'time': tem, "data": []}))
            return False

    # 上传webshell
    def upload_shell(self, data):
        if len(data) == 0: return []
        try:
            shell_data = json.loads(self.ReadFile(self.__webshell))
        except:
            shell_data=[]
            public.WriteFile(self.__webshell, json.dumps([]))
            os.system('/etc/init.d/nginx restart')
        url = self.get_check_url()
        if not url: return []
        for i in data:
            if not i in shell_data:
                if self.is_white(i):continue
                if not self.check_path(i):
                    if self.upload_file_url(i,url):
                        shell_data.append(i)
        public.WriteFile(self.__webshell,json.dumps(shell_data))
        return True

    def send_btwaf(self,filename):
        if public.M('send_settings').where('name=?', ('Nginx防火墙',)).count():
            data = public.M('send_settings').where('name=?', ('Nginx防火墙',)).field(
                'id,name,type,path,send_type,inser_time,last_time,time_frame').select()
            data = data[0]
            if data['send_type']=='dingding':
                self.to_dingding(filename)
            elif data['send_type']=='mail':
                self.to_mail(filename)

    def webshell(self,filename,url):
        try:
            upload_url =url
            size = os.path.getsize(filename)
            if size > 1024000: return False
            upload_data = {'inputfile': self.ReadFile(filename)}
            upload_res = requests.post(upload_url, upload_data, timeout=20).json()
            if upload_res['msg']=='ok':
                if (upload_res['data']['data']['level']==5):
                    print('%s文件为木马  hash:%s' % (filename,upload_res['data']['data']['hash']))
                    self.send_baota2(filename)
                    self.send_btwaf(filename)
                    self.__write_log('Nginx防火墙告警', '%s文件为木马' % filename)
                    return True
                elif upload_res['data']['level'] >= 3:
                    print('%s可疑文件,建议手工检查' % filename)
                    self.__write_log('Nginx防火墙告警','%s可疑文件,建议手工检查' % filename)
                    self.send_baota2(filename)
                    self.send_btwaf(filename)
                    return False
                return False
        except:
            return False
    #get_url
    def get_check_url(self):
        try:
            ret=requests.get('http://www.bt.cn/checkWebShell.php').json()
            if ret['status']:
                return ret['url']
            return False
        except:
            return False

    def upload_file_url(self, filename,url):
        try:
            if os.path.exists(filename):
                return self.webshell(filename,url)
            else:
                return False
        except:
             return False

    def get_ip(self):
        if os.path.exists('/www/server/panel/data/iplist.txt'):
            data=self.ReadFile('/www/server/panel/data/iplist.txt')
            return data.strip()
        else:return '127.0.0.1'

    def to_mail(self,file):
        tongdao = self.__mail.get_settings()
        title='宝塔防火墙提醒您'+self.get_ip()+'服务器正在遭受webshell攻击请及时处理'
        body='宝塔防火墙提醒您'+self.get_ip()+'服务器存在webshell。webshell路径为'+file+'如有误报、请根据防火墙提供的拦截日志,点击误报。如需关闭webshell查杀。请在【Nginx防火墙】-->【全局设置】-->【webshell查杀】关闭即可'
        return self.__mail.qq_smtp_send(str(tongdao['user_mail']['info']['qq_mail']), title=title, body=body)

    def to_dingding(self,file):
        body = '宝塔防火墙提醒您'+self.get_ip() + '服务器存在webshell攻击请及时处理。webshell路径为' + file +'如有误报、请根据防火墙提供的拦截日志,点击误报。如需关闭webshell查杀。请在【Nginx防火墙】-->【全局设置】-->【webshell查杀】关闭即可'
        return self.__mail.dingding_send(body)

    def read_file_md5(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False
    def send_baota2(self, filename):
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata = {'codetxt': self.ReadFile(filename), 'md5': self.read_file_md5(filename), 'type': '0',
                 'host_ip': public.GetLocalIp(), 'size': os.path.getsize(filename)}
        ret = public.httpPost(cloudUrl, pdata)
        return True

    def __write_log(self,name, msg):
        public.WriteLog(name, msg)

if __name__ == '__main__':
   aa=webshell_check().send_san_dir()
