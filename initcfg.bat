@echo off
If Not Exist "userapiconfig.py" Copy "apiconfig.py" "userapiconfig.py"
If Not Exist "user-config.json" Copy "config.json" "user-config.json"
If Not Exist "usermysql.json" Copy "mysql.json" "usermysql.json"
