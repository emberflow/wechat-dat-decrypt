@echo off
cd /d "D:\Projects\wechat-dat-decrypt"
start "" pyw -3 "D:\Projects\wechat-dat-decrypt\gui_picker.py"
if errorlevel 1 (
  py -3 "D:\Projects\wechat-dat-decrypt\gui_picker.py"
  pause
)
