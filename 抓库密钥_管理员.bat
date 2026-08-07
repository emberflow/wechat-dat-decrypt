@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 将请求管理员权限以扫描微信进程内存…
powershell -NoProfile -Command "Start-Process -FilePath 'py' -ArgumentList '-3','scan_db_keys.py' -WorkingDirectory '%cd%' -Verb RunAs -Wait"
echo.
echo 若成功，继续解密数据库…
py -3 pipeline_db.py
pause
