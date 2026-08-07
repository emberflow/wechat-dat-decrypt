@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo  微信图片密钥抓取（监控模式）
echo ========================================
echo.
echo 1. 保持本窗口开着
echo 2. 切到微信，打开「我妈」聊天
echo 3. 连续点开 2~3 张大图
echo 4. 看到「已保存密钥」即可关闭本窗口
echo.
py -3 wechat_img.py monitor-key
pause
