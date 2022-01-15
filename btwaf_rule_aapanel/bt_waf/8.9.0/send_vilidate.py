#!/usr/bin/python
#coding: utf-8
#-----------------------------
# Author: 梁凯强 <1249648969@qq.com>
# 验证码生产器
#-----------------------------
import sys, os
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
os.chdir('/www/server/panel')
sys.path.append("class/")
import vilidate,time,public,json
send_num2 = {}
send_num1 = []

#保存文件
def file_save(name,data):
    path='/www/server/btwaf/captcha/'+name
    f=open(path,'wb')
    f.write(data)
    f.close()
def send_vaildate(num):
    try:
        import vilidate, time
    except:
        public.ExecShell("pip install Pillow==5.4.1 -I")
        return "Pillow not install!"
    vie = vilidate.vieCode()
    codeImage = vie.GetCodeImage(80, 4)
    if sys.version_info[0] == 2:
        try:
            from cStringIO import StringIO
        except:
            from StringIO import StringIO
        out = StringIO()
    else:
        from io import BytesIO
        out = BytesIO()
    codeImage[0].save(out, "png")
    out.seek(0)
    send_num1.append(str(num)+'_'+''.join(codeImage[1]).lower())
    send_num2[num] = ''.join(codeImage[1]).lower()
    file_save(str(num)+'_'+''.join(codeImage[1]).lower()+'.png',out.read())
if os.path.exists('/www/server/btwaf/captcha'):public.ExecShell('rm -rf  /www/server/btwaf/captcha')
if not os.path.exists('/www/server/btwaf/captcha'):public.ExecShell('mkdir -p /www/server/btwaf/captcha && chown www:www /www/server/btwaf/captcha')
print('正在生成验证码！！')
[send_vaildate(i) for i in  range(1,201)]
if len(send_num1)>=1:public.WriteFile('/www/server/btwaf/captcha/num1.json',json.dumps(send_num1))
if len(send_num2)>=1:public.WriteFile('/www/server/btwaf/captcha/num2.json',json.dumps(send_num2))
print('验证码已经生成完成！！')
public.ServiceReload()
