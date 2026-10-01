@echo off
rem ===========================================================================
rem  T9100 / VN300E (UNISOC UMS9620) - full partition backup (READ-ONLY)
rem ---------------------------------------------------------------------------
rem  本脚本只做备份：只读 GPT + 全分区 dump + 生成 SHA256，
rem  不含任何 write / erase / repartition 命令。
rem
rem  前置：把第三方刷机工具放到下面任一个位置
rem    (a) 与本脚本同目录的 bin\ 子目录   或
rem    (b) 与本脚本同目录
rem  需要的文件（来自 CVE-2022-38694 工具包，见仓库 README）：
rem    spd_dump.exe  Channel9.dll  Channel.ini
rem    fdl1-dl.bin   fdl2-dl.bin   custom_exec_no_verify_65012f48.bin
rem
rem  进 BROM：设备完全关机 -> 按住 音量- 不松手 -> 插入 USB
rem             (若进不去，可再试 电源+音量上 或 三键同按)
rem ===========================================================================

setlocal EnableExtensions EnableDelayedExpansion

title T9100 UMS9620 BACKUP

set "ROOT=%~dp0"
set "BIN=%ROOT%bin"
if not exist "%BIN%\spd_dump.exe" set "BIN=%ROOT%"
set "BACKUP_ROOT=%ROOT%backup"

echo ================================================================
echo                 T9100 UMS9620 BACKUP
echo ================================================================
echo.
echo Root:
echo %ROOT%
echo.
echo Bin:
echo %BIN%
echo.

if not exist "%BIN%\spd_dump.exe" (
    echo [ERROR] spd_dump.exe not found.
    echo %BIN%\spd_dump.exe
    pause
    exit /b 1
)

if not exist "%BIN%\custom_exec_no_verify_65012f48.bin" (
    echo [ERROR] custom_exec_no_verify_65012f48.bin not found.
    echo %BIN%\custom_exec_no_verify_65012f48.bin
    pause
    exit /b 2
)

if not exist "%BIN%\fdl1-dl.bin" (
    echo [ERROR] fdl1-dl.bin not found.
    echo %BIN%\fdl1-dl.bin
    pause
    exit /b 3
)

if not exist "%BIN%\fdl2-dl.bin" (
    echo [ERROR] fdl2-dl.bin not found.
    echo %BIN%\fdl2-dl.bin
    pause
    exit /b 4
)

if not exist "%BACKUP_ROOT%" mkdir "%BACKUP_ROOT%"

if not exist "%BACKUP_ROOT%\." (
    echo [ERROR] Cannot create backup directory.
    echo %BACKUP_ROOT%
    pause
    exit /b 5
)

for /f %%A in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%A"

set "BACKUP_DIR=%BACKUP_ROOT%\T9100_!STAMP!"
set "LOG_FILE=!BACKUP_DIR!\backup.log"
set "SHA_FILE=!BACKUP_DIR!\SHA256SUMS.txt"

mkdir "!BACKUP_DIR!"

if not exist "!BACKUP_DIR!\." (
    echo [ERROR] Cannot create session directory.
    echo !BACKUP_DIR!
    pause
    exit /b 6
)

echo.
echo Backup directory:
echo !BACKUP_DIR!
echo.
echo Device       : UNISOC UMS9620
echo Storage      : eMMC
echo Exec address : 0x65012f48
echo FDL1 address : 0x65000800
echo FDL2 address : 0xb4fffe00
echo.
echo Actions:
echo   Read GPT
echo   Save partition XML
echo   Read splloader
echo   Read all normal GPT partitions
echo   Generate SHA256
echo.
echo Excluded by r all:
echo   userdata
echo   cache
echo   blackbox
echo.
echo No write command.
echo No erase command.
echo No repartition command.
echo.
echo ================================================================
echo.
echo Power off the T9100.
echo Connect USB using the same method that previously worked.
echo.
pause

echo.
echo [START] %date% %time%
echo.

(
echo ================================================================
echo T9100 UMS9620 BACKUP LOG
echo Start: %date% %time%
echo Backup directory: !BACKUP_DIR!
echo ================================================================
echo.
) > "!LOG_FILE!"

if not exist "!LOG_FILE!" (
    echo [ERROR] Cannot create log file.
    echo !LOG_FILE!
    pause
    exit /b 7
)

echo [INFO] Log file:
echo !LOG_FILE!
echo.
echo [INFO] Starting spd_dump...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Set-Location -LiteralPath '%BIN%'; & '.\spd_dump.exe' --wait 300 exec_addr 0x65012f48 fdl '.\fdl1-dl.bin' 0x65000800 fdl '.\fdl2-dl.bin' 0xb4fffe00 exec path '%BACKUP_DIR%' r splloader r all reset 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath '%LOG_FILE%' -Append; $code=$LASTEXITCODE; exit $code }"

set "SPD_EXIT=%ERRORLEVEL%"

echo.
echo ================================================================
echo                 SPD_DUMP FINISHED
echo ================================================================
echo.
echo Exit code:
echo !SPD_EXIT!
echo.
echo Backup directory:
echo !BACKUP_DIR!
echo.

echo ================================================================
echo                 FILE CHECK
echo ================================================================
echo.

if exist "!BACKUP_DIR!\splloader.bin" (
    for %%A in ("!BACKUP_DIR!\splloader.bin") do set "SIZE=%%~zA"
    echo [OK] splloader.bin - !SIZE! bytes
) else (
    echo [MISSING] splloader.bin
)

if exist "!BACKUP_DIR!\pgpt.bin" (
    for %%A in ("!BACKUP_DIR!\pgpt.bin") do set "SIZE=%%~zA"
    echo [OK] pgpt.bin - !SIZE! bytes
) else (
    echo [MISSING] pgpt.bin
)

set "XML_FOUND=0"

for %%F in ("!BACKUP_DIR!\partition_*.xml") do (
    if exist "%%F" (
        echo [OK] %%~nxF
        set "XML_FOUND=1"
    )
)

if "!XML_FOUND!"=="0" (
    echo [MISSING] partition XML
)

echo.
echo ================================================================
echo                 KEY PARTITION CHECK
echo ================================================================
echo.

call :CHECK_FILE prodnv.bin
call :CHECK_FILE miscdata.bin
call :CHECK_FILE misc.bin
call :CHECK_FILE persist.bin
call :CHECK_FILE calinv.bin

call :CHECK_FILE trustos_a.bin
call :CHECK_FILE trustos_b.bin

call :CHECK_FILE sml_a.bin
call :CHECK_FILE sml_b.bin

call :CHECK_FILE uboot_a.bin
call :CHECK_FILE uboot_b.bin

call :CHECK_FILE boot_a.bin
call :CHECK_FILE boot_b.bin

call :CHECK_FILE vendor_boot_a.bin
call :CHECK_FILE vendor_boot_b.bin

call :CHECK_FILE init_boot_a.bin
call :CHECK_FILE init_boot_b.bin

call :CHECK_FILE dtb_a.bin
call :CHECK_FILE dtb_b.bin

call :CHECK_FILE dtbo_a.bin
call :CHECK_FILE dtbo_b.bin

call :CHECK_FILE super.bin

call :CHECK_FILE vbmeta_a.bin
call :CHECK_FILE vbmeta_b.bin

call :CHECK_FILE metadata.bin

call :CHECK_FILE common_rs1_a.bin
call :CHECK_FILE common_rs1_b.bin

call :CHECK_FILE common_rs2_a.bin
call :CHECK_FILE common_rs2_b.bin

call :CHECK_FILE ise_a.bin
call :CHECK_FILE ise_b.bin
call :CHECK_FILE isedata.bin

echo.
echo ================================================================
echo                 SHA256
echo ================================================================
echo.

powershell -NoProfile -Command "Get-ChildItem -LiteralPath '%BACKUP_DIR%' -Filter '*.bin' -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 | ForEach-Object { '{0}  {1}' -f $_.Hash, $_.Path } | Set-Content -Encoding ASCII '%SHA_FILE%'"

if exist "%SHA_FILE%" (
    echo [OK] SHA256SUMS.txt
) else (
    echo [ERROR] SHA256SUMS.txt was not created
)

echo.
echo ================================================================
echo                 BACKUP SUMMARY
echo ================================================================
echo.

for /f %%A in ('powershell -NoProfile -Command "(Get-ChildItem -LiteralPath '%BACKUP_DIR%' -Filter '*.bin' -File | Measure-Object).Count"') do set "BIN_COUNT=%%A"

for /f %%A in ('powershell -NoProfile -Command "[math]::Round(((Get-ChildItem -LiteralPath '%BACKUP_DIR%' -Filter '*.bin' -File | Measure-Object Length -Sum).Sum / 1GB),3)"') do set "TOTAL_GB=%%A"

echo Backup directory:
echo !BACKUP_DIR!
echo.
echo BIN count:
echo !BIN_COUNT!
echo.
echo BIN total size:
echo !TOTAL_GB! GB
echo.
echo Log:
echo !LOG_FILE!
echo.
echo SHA256:
echo !SHA_FILE!
echo.

if "!SPD_EXIT!"=="0" (
    echo ================================================================
    echo BACKUP PROCESS FINISHED
    echo ================================================================
) else (
    echo ================================================================
    echo BACKUP PROCESS RETURNED ERROR
    echo ================================================================
    echo Exit code: !SPD_EXIT!
)

echo.
pause
exit /b !SPD_EXIT!


:CHECK_FILE

if exist "!BACKUP_DIR!\%~1" (
    for %%A in ("!BACKUP_DIR!\%~1") do set "FILESIZE=%%~zA"
    echo [OK] %~1 - !FILESIZE! bytes
) else (
    echo [MISSING] %~1
)

goto :eof