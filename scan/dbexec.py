#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-06-27
# @Version : V0.1

import sqlite3
'''
数据库格式
CREATE TABLE scaninfo(id integer primary key AUTOINCREMENT ,ip char(100),osfinger char(100),port char(100),portfinger char(100),portversion char(100));
'''
class DBexec():
    def __init__(self,sql):
        self.sql = sql

    def exec(self):
        conn = sqlite3.connect('scanresult.db')
        cursor = conn.cursor()
        cursor.execute(self.sql)
        scanresult = cursor.fetchall()
        cursor.close()
        conn.commit()
        conn.close()
        return scanresult


