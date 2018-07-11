#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-06-27
# @Version : V0.1
# FoxRoot

import tkinter
import tkinter.messagebox
from tkinter import ttk
import threading
import IPy
import time
import xlwt
from scan import scanner
from scan import dbexec

class Gui():

    def __init__(self):
        self.var1 = ''
        self.var2 = ''
        self.root = tkinter.Tk()

    # 调用扫描模块
    def Inputscan(self):
        # 获取输入网段
        ipsub = str(self.var1.get())
        # 获取输入port
        portsub = str(self.var2.get())
        # 获取速度等级
        level = str(self.var3.get())
        # 检查网段格式
        try:
            IPy.IP(ipsub)
        except:
            tkinter.messagebox.showinfo('错误','网段输入错误')
            return -1
        # 检查端口格式
        try:
            if ',' in portsub:
                for p in portsub.split(','):
                    if int(p)>65535:
                        tkinter.messagebox.showinfo('错误', '端口输入错误')
                        return -1
            elif '-' in portsub:
                p = portsub.split('-')
                if(len(p) == 2):
                    if int(p[1]) > 65535 or int(0) > int(1):
                        tkinter.messagebox.showinfo('错误', '端口输入错误')
                        return -1
                else:
                    tkinter.messagebox.showinfo('错误', '端口输入错误')
                    return -1
            else:
                try:
                    if int(portsub)>65535:
                        tkinter.messagebox.showinfo('错误', '端口输入错误')
                        return -1
                except:
                    tkinter.messagebox.showinfo('错误', '端口输入错误')
                    return -1
        except Exception as e:
            print(e)
            tkinter.messagebox.showinfo('错误', '端口输入错误')
            return -1
        # 检查扫描速度格式
        try:
            int(level)
            if(int(level)<1):
                tkinter.messagebox.showinfo('错误', '扫描速度输入错误')
        except :
            tkinter.messagebox.showinfo('错误', '扫描速度输入错误')
            return -1
        # 调用导入Scan模块
        def Importscan(ipsub, portsub,level):
            sr = scanner.Scan(scanip=ipsub, scanport=portsub, scanlevel=level)
            sr.Masscan_port()
            sr.Nmapscan_sV()
        # 检测扫描线程模块
        def checkth(thr,ipsub):
            # 线程存活性检测
            while thr.is_alive():
                time.sleep(2)
            # 扫描完成提示
            tkinter.messagebox.showinfo('提示', ipsub + ' 扫描完成')
            return 0
        # 开启扫描的子线程
        thr = threading.Thread(target=Importscan,args=(ipsub,portsub,level))
        thr.start()
        # 开启检测扫描线程的子线程
        threading.Thread(target=checkth,args=(thr,ipsub)).start()

    # 调用输出模块
    def Outputinfo(self):
        ipsubselect = str(self.var1.get())
        # 检查网段格式
        try:
            IPy.IP(ipsubselect)
        except ValueError:
            tkinter.messagebox.showinfo('错误', '网段输入错误')
            return -1
        # SQL查询
        sql = 'select * from scaninfo group by ip,port'
        scanresult = dbexec.DBexec(sql=sql).exec()
        # 查询无结果提示
        if len(scanresult) == 0:
            tkinter.messagebox.showinfo('提示','该网段无扫描结果')
            return 0
        flag = 0
        for sr in scanresult:
            if sr[1] in IPy.IP(ipsubselect):
                flag = 1
        if flag == 0:
            tkinter.messagebox.showinfo('提示', '该网段无扫描结果')
            return 0
        else:
            self.Biaoge(ipsubselect=ipsubselect,scanresult=scanresult)

    # 设置表格显示查询结果
    def Biaoge(self,ipsubselect,scanresult):
        bgroot = tkinter.Tk()
        bgroot.title(ipsubselect + ' 扫描结果')
        bgroot.geometry('1200x800')
        bgroot.resizable(0, 0)
        tree_date = ttk.Treeview(bgroot,show="headings", height=35)
        tree_date['column'] = ['ip', 'osfinger', 'port', 'portfinger', 'portversion']
        tree_date.pack()
        tree_date.column('ip', width=200)
        tree_date.column('osfinger', width=300)
        tree_date.column('port', width=100)
        tree_date.column('portfinger', width=200)
        tree_date.column('portversion', width=300)
        tree_date.heading('ip', text='IP地址')
        tree_date.heading('osfinger', text='系统指纹')
        tree_date.heading('port', text='端口')
        tree_date.heading('portfinger', text='端口服务')
        tree_date.heading('portversion', text='端口服务版本')
        newscanresult = []
        for sr in scanresult:
            if sr[1] in IPy.IP(ipsubselect):
                tree_date.insert('', 1, values=(sr[1], sr[2], sr[3], sr[4], sr[5]))
                newscanresult.append(sr)
        tree_date.pack()
        tkinter.Button(bgroot, text='统计', command=lambda: self.Tongji(srlts=newscanresult), font=('Helvetica', 10, 'bold'),fg='red').place(relx=0.42, rely=0.92)
        tkinter.Button(bgroot, text='导出', command=lambda: self.Daochu(srlts=newscanresult), font=('Helvetica', 10, 'bold'),fg='red').place(relx=0.52, rely=0.92)
        bgroot.mainloop()

    # 统计模块
    def Tongji(self,srlts):
        tjroot = tkinter.Tk()
        tjroot.title('统计')
        tjroot.geometry('400x200')
        tjroot.resizable(0,0)
        tj_date = ttk.Treeview(tjroot,show="headings",height=8)
        tj_date['column'] = ['key','value']
        tj_date.pack()
        tj_date.column('key',width=200)
        tj_date.column('value',width=200)
        tj_date.heading('key',text='项')
        tj_date.heading('value',text='值')
        ipinfo = {}
        portinfo = {}
        for srlt in srlts:
            if srlt[1] in ipinfo:
                ipinfo[srlt[1]].append(srlt[3])
            else:
                lis = [srlt[3]]
                ipinfo[srlt[1]] = lis
            if srlt[3] in portinfo:
                portinfo[srlt[3]].append(srlt[1])
            else:
                lis = [srlt[1]]
                portinfo[srlt[3]] = lis
        tj_date.insert('', 1, values=('IP地址',str(len(ipinfo.keys()))+'个'))
        for h, n in portinfo.items():
            tj_date.insert('', 1, values=('端口 '+str(h), str(len(n))+'个'))

    # 扫描结果导出到execl
    def Daochu(self,srlts):
        xlwtwork = xlwt.Workbook(encoding='utf-8')
        ws = xlwtwork.add_sheet('info')
        ws.write(0, 0, 'IP')
        ws.write(0, 1, '操作系统版本')
        ws.write(0, 2, '端口')
        ws.write(0, 3, '服务')
        ws.write(0, 4, '服务版本')
        order = 1
        for i in range(0,len(srlts),1):
            ws.write(order, 0, srlts[i][1])
            ws.write(order, 1, srlts[i][2])
            ws.write(order, 2, srlts[i][3])
            ws.write(order, 3, srlts[i][4])
            ws.write(order, 4, srlts[i][5])
            order = order + 1
        xlwtwork.save('./scaninfo.xls')

    # 清空数据库缓存模块
    def Clear(self):
        sql = 'delete from scaninfo'
        dbexec.DBexec(sql=sql).exec()
        tkinter.messagebox.showinfo('提示', '成功清除扫描缓存')

    # 主窗口和标签界面展示
    def Display(self):
        # 设置主窗口,窗口title,窗口大小
        self.root.title('Masscan-NmapToScan')
        self.root.geometry('300x600')
        self.root.resizable(0, 0)
        # 设置显示标签
        tkinter.Label(self.root, text='互联网主机扫描。\n可批量IP，批量端口扫描。', font=(10), fg='red').place(relx=0.18, rely=0.05)  # 创建标签类，说明
        tkinter.Label(self.root, text='输入网段（192.168.0.0/24）', font=(6)).place(relx=0.05, rely=0.20)  # 创建标签类，ip
        tkinter.Label(self.root, text='输入端口（22,80 or 1-1000）', font=(6)).place(relx=0.05, rely=0.30)  # 创建标签类，port
        tkinter.Label(self.root, text='输入速度（1-X）：', font=(6)).place(relx=0.05, rely=0.40)  # 创建标签类，level
        # 设置ip输入框
        self.var1 = tkinter.StringVar()
        entry1 = tkinter.Entry(self.root, validate='key',textvariable=self.var1, font=(10), width=22)
        entry1.place(relx=0.05, rely=0.25)
        # 设置port输入框
        self.var2 = tkinter.StringVar()
        entry2 = tkinter.Entry(self.root, validate='key',textvariable=self.var2, font=(10), width=22)
        entry2.place(relx=0.05, rely=0.35)
        # 设置level输入框
        self.var3 = tkinter.StringVar()
        entry3 = tkinter.Entry(self.root, validate='key', textvariable=self.var3, font=(10), width=22)
        entry3.place(relx=0.05, rely=0.45)
        # 设置button按钮
        tkinter.Button(self.root, text='添加扫描任务', command=self.Inputscan, font=('Helvetica', 10, 'bold'), fg='red').place(relx=0.30, rely=0.55)  # 创建按钮和事件处理，点击按钮进行端口扫描
        tkinter.Button(self.root, text='查询扫描结果', command=self.Outputinfo, font=('Helvetica', 10, 'bold'),fg='red').place(relx=0.30, rely=0.65)  # 创建按钮和时间处理，点击按钮进行查询
        tkinter.Button(self.root, text='清空扫描缓存', command=self.Clear, font=('Helvetica', 10, 'bold'), fg='red').place(relx=0.30,rely=0.75) # 创建程序清除扫描缓存处理，点击按钮清空扫描缓存
        tkinter.Button(self.root, text='退出工具', command=exit, font=('Helvetica', 10, 'bold'), fg='red').place(relx=0.35, rely=0.85)  # 创建程序退出按钮，点击按钮退出程序
        # 开启窗口事件循环
        self.root.mainloop()