@echo off
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set "ATLAS_VS=%%i"
if not defined ATLAS_VS exit /b 1
call "%ATLAS_VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

pushd "%~dp0..\.."
if not exist artifacts\pe-linkage-probe mkdir artifacts\pe-linkage-probe
cl /nologo /LD /O2 /W4 /WX tests\PeLinkageProbe\Provider.c /Foartifacts\pe-linkage-probe\Provider.obj /Feartifacts\pe-linkage-probe\AtlasLinkageProvider.dll /link /DEF:tests\PeLinkageProbe\Provider.def /Brepro
if errorlevel 1 exit /b 1

cl /nologo /LD /O2 /W4 /WX tests\PeLinkageProbe\Consumer.c /Foartifacts\pe-linkage-probe\Consumer.obj /Feartifacts\pe-linkage-probe\AtlasLinkageConsumer.dll /link artifacts\pe-linkage-probe\AtlasLinkageProvider.lib user32.lib delayimp.lib /DELAYLOAD:user32.dll /Brepro
if errorlevel 1 exit /b 1
popd
