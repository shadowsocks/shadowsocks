#!/usr/bin/env python
# -*- coding: utf-8 -*-
import config
import logging
import cymysql
import re
from flask import Flask,request,session,redirect,render_template
if config.LOG_ENABLE:
    logging.basicConfig(
        filename=config.LOG_FILE,
        level=config.LOG_LEVEL,
        datefmt='%Y-%m-%d %H:%M:%S',
        format='%(asctime)s %(levelname)s %(filename)s[%(lineno)d] %(message)s'
    )
app = Flask(__name__)
app.secret_key = 'asdjhlasdlkjahskldhakjshd782934879123987*(Z&*(&98237498'

def get_mysql_conn():
    conn = cymysql.connect(host=config.MYSQL_HOST, port=config.MYSQL_PORT, user=config.MYSQL_USER,
                           passwd=config.MYSQL_PASS, db=config.MYSQL_DB, charset='utf8')
    return conn;
def validateEmail(email):
    if len(email) > 4:
        if re.match("\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*", email) != None:
            return True
    return False
@app.route("/")
def index():
    if 'uid' in session:
        conn = get_mysql_conn()
        cur = conn.cursor(cursor=cymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM user WHERE id=%s",(session['uid']))
        userinfo = cur.fetchone()
        cur.close()
        conn.close()
        return render_template("index.html",user=userinfo)
    return redirect("/login")
@app.route("/login",methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form["username"]
        password = request.form["password"]
        if(validateEmail(email)):
            conn = get_mysql_conn()
            cur = conn.cursor(cursor=cymysql.cursors.DictCursor)
            cur.execute("SELECT * FROM user WHERE u_email=%s",(email))
            userinfo = cur.fetchone()
            cur.close()
            conn.close()
            if(userinfo == None or userinfo["u_pwd"] != password):
                return render_template("login.html", errormsg=u"用户不存在或者密码错误")
            else:
                session['uid']=userinfo['id']
                return redirect("/")
        else:
            return render_template("login.html", errormsg=u"邮件格式错误")
    else:
        return render_template("login.html")
@app.route('/logout')
def logout():
    session.pop('uid', None)
    return redirect("/login")
@app.route('/update_ss_pwd',methods=['POST'])
def update_ss_pwd():
    if 'uid' in session:
        ss_pwd = request.form["ss_pwd"]
        conn = get_mysql_conn()
        cur = conn.cursor(cursor=cymysql.cursors.DictCursor)
        update_sql = "update user set ss_pwd=%s where id=%s"
        cur.execute(update_sql,(ss_pwd,session['uid']))
        cur.close()
        conn.close()
        return u"修改成功"
    else:
        return u"修改失败"
if __name__ == "__main__":
    app.run(host='0.0.0.0')
