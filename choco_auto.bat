@echo off

REM REF: https://github.com/koppor/koppors-chocolatey-scripts

echo ####################################################
echo This will first install chocolatey, then other tools
echo.
echo Browse https://chocolatey.org/packages for packages
echo.
echo Ensure that your cmd.exe runs as Administrator
echo  
echo If at university, disable any proxy in the Internet Explorer Network settings.
echo.
pause
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin
choco feature enable -n=allowGlobalConfirmation
pause

echo Now chocolatey should be ready and we can go ahead
echo.
pause

:: choco install keepass
choco install firefox
choco pin add -n=firefox

choco install googlechrome
choco pin add -n=googlechrome

rem Required for advanced Window management
:: choco install powertoys

choco install notepadplusplus

choco install 7zip

rem AdoptOpenJDK on stereoids
choco install libericajdkfull

choco install windirstat

rem This is interactive - therefore no installation
rem choco install windowsessentials

choco install vlc

REM REF: https://riptutorial.com/batch-file/example/28274/echo-to-create-files
REM REF: https://stackoverflow.com/questions/3294599/do-batch-files-support-multiline-variables
  
REM Create C:\down
mkdir C:\down

REM Create C:\down\update-all.bat
REM ###################################
REM Creating a Newline variable (the two blank lines are required!)
SET NLM=^

SET NL=^^^%NLM%%NLM%^%NLM%%NLM%

REM use a unique character (here +) to indicate a newline, then replace it later
SET banner=@echo off +^
 +^
echo Disabling proxies...  +^
set HTTP_PROXY= +^
set HTTPS_PROXY= +^
echo . +^
 +^
echo Updating all packages... +^
call choco upgrade all +^
echo .

setlocal enabledelayedexpansion
SET banner=%banner:+=!NL!%
setlocal disabledelayedexpansion
echo %banner% > C:\down\update-all.bat

REM ###########################
REM End C:\down\update-all.bat
:END

echo To keep your system updated, run C:\down\update-all.bat regularly from an administrator CMD.exe.
pause
