@echo off
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set "ATLAS_VS=%%i"
if not defined ATLAS_VS exit /b 1
call "%ATLAS_VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

pushd "%~dp0..\.."
if not exist artifacts\pinvoke-provider mkdir artifacts\pinvoke-provider
cl /nologo /LD /O2 /W4 /WX tests\PInvokeProbe\Provider.c /Foartifacts\pinvoke-provider\Provider.obj /Feartifacts\pinvoke-provider\AtlasPInvokeProvider.dll /link /DEF:tests\PInvokeProbe\Provider.def /Brepro
if errorlevel 1 exit /b 1
popd
