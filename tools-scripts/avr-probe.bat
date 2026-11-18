@echo off
REM ============================================================================
REM  avr-probe.bat —— 联想 Y70 新一代 / moto edge 70 max (avr) 真机体检
REM                   全程只读，不改任何东西，不需要 root。
REM  Windows cmd 用。别在命令里加单引号（'...' 会被当成命令名的一部分）。
REM ============================================================================
setlocal
set ADB=adb
set OUT=device_probe_out
if not exist %OUT% mkdir %OUT%

echo.
echo ==================== [0] 设备在线检查 ====================
%ADB% get-state > %OUT%\00_state.txt 2>&1
type %OUT%\00_state.txt
for /f %%i in ('%ADB% get-state 2^>nul') do set STATE=%%i
if not "%STATE%"=="device" (
  echo [X] 没有检测到设备，先确认 USB 调试已授权 / adb devices 能看到
  goto :eof
)

echo.
echo ==================== [1] 身份：shell 所属组 / 机型 / build ====================
%ADB% shell id                                  > %OUT%\01_id.txt 2>&1
%ADB% shell getprop ro.product.device           >> %OUT%\01_id.txt 2>&1
%ADB% shell getprop ro.product.model            >> %OUT%\01_id.txt 2>&1
%ADB% shell getprop ro.build.id                 >> %OUT%\01_id.txt 2>&1
%ADB% shell getprop ro.build.fingerprint        >> %OUT%\01_id.txt 2>&1
%ADB% shell getprop ro.kernel.version           >> %OUT%\01_id.txt 2>&1
type %OUT%\01_id.txt

echo.
echo ==================== [2] 内核串（必须与 payload 逐字符一致）====================
%ADB% shell cat /proc/sys/kernel/osrelease       > %OUT%\02_kernel.txt 2>&1
%ADB% shell cat /proc/version                   >> %OUT%\02_kernel.txt 2>&1
type %OUT%\02_kernel.txt

echo.
echo ==================== [3] perf_event_paranoid（期望 -1）====================
%ADB% shell cat /proc/sys/kernel/perf_event_paranoid > %OUT%\03_paranoid.txt 2>&1
type %OUT%\03_paranoid.txt

echo.
echo ==================== [4] /proc/slabinfo 可读性 ====================
%ADB% shell head -4 /proc/slabinfo                > %OUT%\04_slabinfo.txt 2>&1
type %OUT%\04_slabinfo.txt

echo.
echo ==================== [5] tracefs：kmem_cache_alloc 事件 ====================
%ADB% shell ls /sys/kernel/tracing/events/kmem/kmem_cache_alloc  > %OUT%\05_ls.txt 2>&1
%ADB% shell cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id > %OUT%\05_event_id.txt 2>&1
echo --- ls ---
type %OUT%\05_ls.txt
echo --- event id ---
type %OUT%\05_event_id.txt

echo.
echo ==================== [6] trace_pipe 读取权限（真正决定成败的一条）====================
REM 该文件是 -r--r----- root:readtracefs，shell 必须在 readtracefs 组里才能读
%ADB% shell "timeout 1 sh -c 'head -c 16 /sys/kernel/tracing/trace_pipe' >/dev/null 2>&1; echo rc=$?" > %OUT%\06_tracepipe.txt 2>&1
type %OUT%\06_tracepipe.txt
echo   rc=0 或 rc=124(timeout 说明能打开且在等数据) = 可读；rc=1/126/13 = 不可读
%ADB% shell "ls -lZ /sys/kernel/tracing/trace_pipe" >> %OUT%\06_tracepipe.txt 2>&1

echo.
echo ==================== [7] /data/local/tmp 可写（payload 落地目录）====================
%ADB% shell "mkdir -p /data/local/tmp/a && echo ok > /data/local/tmp/a/.probe && cat /data/local/tmp/a/.probe" > %OUT%\07_writable.txt 2>&1
type %OUT%\07_writable.txt

echo.
echo ==================== [8] 已装的 root 管理器 ====================
%ADB% shell pm list packages 2>nul | findstr /i "weishu kernelsu ksu sukisu resukisu baka kow shizuku" > %OUT%\08_ksu.txt 2>&1
type %OUT%\08_ksu.txt

echo.
echo ==================== [9] 现有 payload / 日志残留 ====================
%ADB% shell "ls -l /data/local/tmp/a/ 2>/dev/null; echo ---; tail -5 /data/local/tmp/timer.log 2>/dev/null" > %OUT%\09_leftover.txt 2>&1
type %OUT%\09_leftover.txt

echo.
echo ==================== [10] tracefs 写权限（真正决定 exploit 能不能跑）====================
REM exploit 要写 events/kmem/rss_stat/trigger、tracing_on、buffer_size_kb。
REM shell 通常只有 readtracefs 只读组 —— 读得到不等于写得进。
%ADB% shell "echo 0 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>/dev/null && echo W_OK || echo W_FAIL" > %OUT%\10_tracefs_write.txt 2>&1
%ADB% shell "v=$(cat /sys/kernel/tracing/tracing_on 2>/dev/null); echo $v > /sys/kernel/tracing/tracing_on 2>/dev/null && echo T_OK || echo T_FAIL" >> %OUT%\10_tracefs_write.txt 2>&1
%ADB% shell "head -c 0 /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw >/dev/null 2>&1 && echo R_OK || echo R_FAIL" >> %OUT%\10_tracefs_write.txt 2>&1
%ADB% shell "ls -l /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable" >> %OUT%\10_tracefs_write.txt 2>&1
type %OUT%\10_tracefs_write.txt
echo   W_OK=能写（可用） / W_FAIL=不能写（exploit 跑不起来）

echo.
echo ================================================================
echo  结果已保存在 %OUT%\   （共 11 个 txt，直接打包发我）
echo  判定口径：
echo    [1] id 里要能看到 readtracefs
echo    [2] 必须是 6.12.58-android16-6-gb0a9599c6c01-ab14987696-4k
echo    [3] 必须是 -1
echo    [4] 必须能打出 slabinfo 表头
echo    [6] rc 不能是 13/126（Permission denied）
echo ================================================================
endlocal
