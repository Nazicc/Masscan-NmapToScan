#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-06-27
# @Version : V0.1
# FoxRoot

import nmap
import os
import sys
import re
import threading
import queue
import time
from scan import dbexec

class Scan():

    # 定义全局变量
    def __init__(self,scanip,scanport,scanlevel):
        self.scanip = scanip
        self.scanport = scanport
        self.scanlevel = scanlevel
        self.info_ip = {}

    # masscan快速扫描开放的端口
    def Masscan_port(self):
        # 用os库调用masscan进行扫描
        if(os.name == 'posix'):     #linux
            os.system('chmod +x ./masscan/masscan')
            # --rate 1000 发包速 1000 --wait 扫描全部结束后等待3秒用于接受剩余返回包
            mscan = os.popen('./masscan/masscan --rate 1000 --wait 3 -p ' + self.scanport + ' ' + self.scanip)
        elif(os.name == 'nt'):   #windows
            # --rate 1000 发包速 1000 --wait 扫描全部结束后等待3秒用于接受剩余返回包
            mscan = os.popen('.\masscan\masscan.exe --rate 1000 --wait 3 -p ' + self.scanport + ' ' + self.scanip)
        mscanresule = mscan.read()
        mscaninfolist = mscanresule.strip('\n').split('\n')
        for info in mscaninfolist:
            # 利用正则从masscan的扫描信息中过滤端口和IP地址
            reinfo = re.search(re.compile(r'Discovered open port (\d+?)/tcp on (.*)'),info.strip(' '))
            if(reinfo == None):
                # print('\n[-] 该网段无符合条件主机.')
                sys.exit(0)
            # 以IP地址为单位统计端口开放信息
            if(reinfo.group(2) in self.info_ip):
                self.info_ip[reinfo.group(2)].append(reinfo.group(1))
            else:
                lis = [reinfo.group(1)]
                self.info_ip[reinfo.group(2)] = lis

    # nmap识别开放端口的服务版本
    def Nmapscan_sV(self):
        # 设定线程锁，防止shell中输出混乱
        lock = threading.Lock()
        # 通过队列threads1实现多线程的调节与调用
        threads1 = queue.Queue()
        checkthread = []
        for ip in self.info_ip.keys():
            threads1.put(threading.Thread(target=self.nmscans, args=(ip,lock)))
        for i in range(1, threads1.qsize() + 1):
            que = threads1.get()
            que.start()
            checkthread.append(que)
            # 设置扫描速度等级
            if (i % int(self.scanlevel) == 0):
                time.sleep(3)
        # 检查扫描子线程存活
        while len(checkthread)>0:
            time.sleep(2)
            for ckth in checkthread:
                if ckth.is_alive() == False:
                    checkthread.remove(ckth)

    # nmap扫描函数
    def nmscans(self,ip,lock):
        infos = []
        nmscan = nmap.PortScanner()
        for port in self.info_ip[ip]:
            try:
                # nmap扫描参数 -T5:疯狂扫描速度 -Pn:不ping -sV:端口对应服务版本 -O:系统指纹识别
                nminfo = nmscan.scan(hosts=ip, ports=port, arguments='-T5 -Pn -sV -O')
                try:
                    nmserver = nminfo['scan'][ip]['osmatch'][0]['name']
                except:
                    nmserver = 'ERROR 获取信息失败'
                try:
                    nmname = nminfo['scan'][ip]['tcp'][int(port)]['name']
                except:
                    nmname = 'ERROR 获取信息失败'
                try:
                    nmproduct = nminfo['scan'][ip]['tcp'][int(port)]['product']
                except:
                    nmproduct = 'ERROR 获取信息失败'
                try:
                    nmversion = nminfo['scan'][ip]['tcp'][int(port)]['version']
                except:
                    nmversion = 'ERROR 获取信息失败'
            except:
                # 因超时丢弃一些端口，导致参数获取不到信息，就置为空
                nmserver = 'ERROR 获取信息超时'
                nmname = 'ERROR 获取信息超时'
                nmproduct = 'ERROR 获取信息超时'
                nmversion = 'ERROR 获取信息超时'
            info = []
            info.append(ip)
            info.append(nmserver)
            info.append(port)
            info.append(nmname)
            info.append(nmproduct)
            info.append(nmversion)
            infos.append(info)
        lock.acquire()
        self.Save_sqllite(infos)
        lock.release()

    # 扫描信息存放到数据库
    def Save_sqllite(self,infos):
        for i in range(0, len(infos), 1):
            sql = 'insert into scaninfo(ip, osfinger, port, portfinger, portversion) values (\'' + str(infos[i][0]) + '\',\'' + str(infos[i][1]) + '\',\'' + str(infos[i][2]) + '\',\'' + str(infos[i][3]) + '\',\'' + str(infos[i][4]) + str(infos[i][5]) + '\')'
            dbexec.DBexec(sql=sql).exec()