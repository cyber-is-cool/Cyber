@ECHO OFF
CLS

:MENU

ECHO.
ECHO ...............................................
ECHO PRESS 1, 2 OR 3 to select your task, or 4 to EXIT.
ECHO.
ECHO 1 - Open Notepad
ECHO 2 - Open Calculator
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

