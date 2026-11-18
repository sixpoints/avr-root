#!/usr/bin/env bash
# avr-probe.sh —— avr 真机体检（只读，不需要 root）。WSL / Git Bash / Linux 用。
# Windows cmd 请用同目录的 avr-probe.bat。
set -uo pipefail
ADB="${ADB:-adb}"
OUT="${OUT:-device_probe_out}"
mkdir -p "$OUT"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
run(){ local n="$1"; shift; "$@" >"$OUT/$n.txt" 2>&1; sed 's/^/  /' "$OUT/$n.txt"; }

"$ADB" get-state >/dev/null 2>&1 || { echo "没有设备：先 adb devices"; exit 1; }

say "[1] 身份 / 机型 / build"
"$ADB" shell id >"$OUT/01_id.txt" 2>&1
for k in ro.product.device ro.product.model ro.build.id ro.build.fingerprint ro.kernel.version; do
  printf '%-24s ' "$k" >>"$OUT/01_id.txt"
  "$ADB" shell getprop "$k" >>"$OUT/01_id.txt" 2>&1
done
sed 's/^/  /' "$OUT/01_id.txt"

say "[2] 内核串（必须与 payload 逐字符一致）"
run 02_kernel sh -c "\"$ADB\" shell cat /proc/sys/kernel/osrelease; \"$ADB\" shell cat /proc/version"

say "[3] perf_event_paranoid（期望 -1）"
run 03_paranoid "$ADB" shell cat /proc/sys/kernel/perf_event_paranoid

say "[4] /proc/slabinfo 可读性"
run 04_slabinfo sh -c "\"$ADB\" shell head -4 /proc/slabinfo"

say "[5] tracefs kmem_cache_alloc"
run 05_tracefs_ls "$ADB" shell ls /sys/kernel/tracing/events/kmem/kmem_cache_alloc
run 05_event_id "$ADB" shell cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id

say "[6] trace_pipe 读取权限（决定成败）"
"$ADB" shell "timeout 1 sh -c 'head -c 16 /sys/kernel/tracing/trace_pipe' >/dev/null 2>&1; echo rc=\$?" >"$OUT/06_tracepipe.txt" 2>&1
"$ADB" shell ls -l /sys/kernel/tracing/trace_pipe >>"$OUT/06_tracepipe.txt" 2>&1
sed 's/^/  /' "$OUT/06_tracepipe.txt"
echo "  rc=0/124 可读；rc=1/13/126 不可读"

say "[7] /data/local/tmp 可写"
run 07_writable "$ADB" shell "mkdir -p /data/local/tmp/a && echo ok > /data/local/tmp/a/.probe && cat /data/local/tmp/a/.probe"

say "[8] 已装 root 管理器"
"$ADB" shell pm list packages 2>/dev/null | grep -iE 'weishu|kernelsu|ksu|sukisu|resukisu|baka|kow|shizuku' >"$OUT/08_ksu.txt" 2>&1
sed 's/^/  /' "$OUT/08_ksu.txt"

say "[9] payload / 日志残留"
run 09_leftover sh -c "\"$ADB\" shell 'ls -l /data/local/tmp/a/ 2>/dev/null; echo ---; tail -5 /data/local/tmp/timer.log 2>/dev/null'"

say "[10] tracefs 写权限（决定 exploit 能不能跑）"
{
  "$ADB" shell "echo 0 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>/dev/null && echo W_OK || echo W_FAIL"
  "$ADB" shell "v=\$(cat /sys/kernel/tracing/tracing_on 2>/dev/null); echo \$v > /sys/kernel/tracing/tracing_on 2>/dev/null && echo T_OK || echo T_FAIL"
  "$ADB" shell "head -c 0 /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw >/dev/null 2>&1 && echo R_OK || echo R_FAIL"
  "$ADB" shell ls -l /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable
} >"$OUT/10_tracefs_write.txt" 2>&1
sed 's/^/  /' "$OUT/10_tracefs_write.txt"
echo "  W_OK=能写 / W_FAIL=不能写（exploit 跑不起来）"

say "完成"
echo "结果目录：$OUT/"
