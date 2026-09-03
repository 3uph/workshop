@echo off
REM Build all loaders on Windows using MSVC (Visual Studio Developer Command Prompt)
REM Run from: Developer Command Prompt for VS

echo ============================================
echo   Building Workshop Loaders (MSVC)
echo ============================================
echo.

REM Part 1: Basic Loaders
echo [*] Building Part 1 Loaders...

cd 1.1_createThread
cl.exe /EHsc /O2 createThread.cpp /Fe:createThread.exe /I.. /link winhttp.lib 2>nul && echo [+] createThread.exe || echo [-] FAILED
cd ..

cd 1.2a_createRemoteThread
cl.exe /EHsc /O2 createRemoteThread.cpp /Fe:createRemoteThread.exe /I.. /link winhttp.lib 2>nul && echo [+] createRemoteThread.exe || echo [-] FAILED
cd ..

cd 1.2b_APCInjection
cl.exe /EHsc /O2 APCInjection.cpp /Fe:APCInjection.exe /I.. /link winhttp.lib 2>nul && echo [+] APCInjection.exe || echo [-] FAILED
cd ..

cd 1.3_localThreadHijack
cl.exe /EHsc /O2 localThreadHijack.cpp /Fe:localThreadHijack.exe /I.. /link winhttp.lib 2>nul && echo [+] localThreadHijack.exe || echo [-] FAILED
cd ..

cd 1.4_Fiber
cl.exe /EHsc /O2 Fiber.cpp /Fe:Fiber.exe /I.. /link winhttp.lib 2>nul && echo [+] Fiber.exe || echo [-] FAILED
cd ..

cd 1.5_simpleRunner
cl.exe /EHsc /O2 simpleRunner.cpp /Fe:simpleRunner.exe /I.. /link winhttp.lib 2>nul && echo [+] simpleRunner.exe || echo [-] FAILED
cd ..

REM Part 2: Module Stomping
echo.
echo [*] Building Part 2 Loaders...

cd 2.0_moduleStomping
cl.exe /EHsc /O2 moduleStomping.cpp /Fe:moduleStomping.exe /I.. /link winhttp.lib 2>nul && echo [+] moduleStomping.exe || echo [-] FAILED
cd ..

cd 2.1_sectionMapping
cl.exe /EHsc /O2 sectionMapping.cpp /Fe:sectionMapping.exe /I.. /link winhttp.lib 2>nul && echo [+] sectionMapping.exe || echo [-] FAILED
cd ..

REM Part 3: Stack Spoofing (needs NASM)
echo.
echo [*] Building Part 3 Loaders (ASM + C++)...

cd 3.1_stackSpoofing
nasm -f win64 asm.asm -o asm.obj 2>nul && echo [+] asm.obj assembled
cl.exe /EHsc /O2 stackSpoofing.cpp asm.obj /Fe:stackSpoofing.exe /I.. /link winhttp.lib 2>nul && echo [+] stackSpoofing.exe || echo [-] FAILED
cd ..

cd 3.2_stackSpoofingIndirectSyscalls
nasm -f win64 asm.asm -o asm.obj 2>nul && echo [+] asm.obj assembled
cl.exe /EHsc /O2 stackSpoofingIndirectSyscalls.cpp asm.obj /Fe:stackSpoofingIndirectSyscalls.exe /I.. /link winhttp.lib 2>nul && echo [+] stackSpoofingIndirectSyscalls.exe || echo [-] FAILED
cd ..

cd 3.3_stackSpoofingStomping
nasm -f win64 asm.asm -o asm.obj 2>nul && echo [+] asm.obj assembled
cl.exe /EHsc /O2 stackSpoofingIndirectStomping.cpp asm.obj /Fe:stackSpoofingIndirectStomping.exe /I.. /link winhttp.lib 2>nul && echo [+] stackSpoofingIndirectStomping.exe || echo [-] FAILED
cd ..

REM Part 4: AI Evasion
echo.
echo [*] Building Part 4 AI Evasion Loader...
cd 4_AI
cl.exe /EHsc /O2 GlobalWeatherMonitor.cpp /Fe:GlobalWeatherMonitor.exe /I.. /link winhttp.lib 2>nul && echo [+] GlobalWeatherMonitor.exe || echo [-] FAILED
cd ..

echo.
echo ============================================
echo   Build Complete
echo ============================================
echo.
echo Next steps:
echo   1. Generate shellcode: bash tools/generate_shellcode.sh (on Kali)
echo   2. Place .bin files in binfile\ directory
echo   3. Update config.conf with payload path
echo   4. Run loaders on Windows target with Elastic Defend in Detection mode
