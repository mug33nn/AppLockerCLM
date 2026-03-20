@echo off
setlocal

set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set PROJECT=%~dp0AppLockerCLM.csproj

echo [*] Building AppLockerCLM...
echo.

%MSBUILD% "%PROJECT%" /p:Configuration=Release /v:minimal /nologo

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build succeeded: %~dp0bin\Release\AppLockerCLM.exe
) else (
    echo.
    echo [X] Build failed - check errors above
)

pause
