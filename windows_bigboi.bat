@ECHO OFF
CLS

:MENU

ECHO.
ECHO ...............................................
ECHO PRESS 1, 2 OR 3 to select your task, or 4 to EXIT.
ECHO.
ECHO 1 - Open Password
ECHO 2 - Open System
ECHO 3 - Open Notepad AND Calculator
ECHO 4 - EXIT
ECHO ...............................................
ECHO.

SET /P M=Type 1, 2, 3, or 4 then press ENTER:
IF %M%==1 GOTO PASS
IF %M%==2 GOTO SYS
IF %M%==3 GOTO OTH
IF %M%==4 GOTO EOF

:SYS

echo Windows Audit
auditpol /set /subcategory:"System" /success:enable /failure:enable
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Object Access" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Tracking" /success:enable /failure:enable

timeout 3 > NUL
cls
ECHO Auto Play disable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
timeout 3 > NUL
cls
ECHO One Drive Startup
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d "C:\Windows\System32\OneDriveSetup.exe /autostart" /f
timeout 3 > NUL
cls
Echo Screen Saver
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "600" /f
timeout 3 > NUL
cls
ECHO Windows Defender Spyware
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
timeout 3 > NUL
cls
:PASS

ECHO Lock out policy
net accounts /lockoutduration:30
net accounts /lockoutthreshold:10
net accounts /lockoutwindow:30
