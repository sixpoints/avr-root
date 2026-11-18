package com.avrroot;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.util.ArrayList;

import rikka.shizuku.Shizuku;

public class MainActivity extends Activity {

    /** 本 fork 适配的两个内核（avr = 联想 Y70 新一代 / moto edge 70 max, XT2611） */
    static final String EXPECT_KERNEL_A16 =
            "6.12.58-android16-6-gb0a9599c6c01-ab14987696-4k";   // W3WWL36.65-48-7
    static final String EXPECT_KERNEL_A17 =
            "6.12.58-android16-6-g09eda8c8505a-ab15950084-4k";   // A171WWH.42-35-16

    /** 已适配的 build id（开机设置，KernelSU 无法伪造） */
    static final String[] EXPECT_BUILDS = {"W3WWL36.65-48-7", "A171WWH.42-35-16"};

    private TextView statusView;
    private TextView logView;
    private Button rootBtn;
    private Button shizukuBtn;
    private Button copyRunLogBtn;
    private Button rebootBtn;
    private Button shutdownBtn;
    private Button softBootBtn;
    private Button openCheckerBtn;
    private Button clearRunLogBtn;
    private EditText pkgEdit;
    private Spinner managerSpinner;
    private SharedPreferences prefs;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean running = false;
    private volatile boolean rooted = false;
    private volatile boolean rootChecked = false;
    private volatile boolean rootChecking = false;

    private static final String CURRENT_SPOOF = "kqvdie.zeykvw.hpbcyd";
    private String[] managerLabels = new String[0];
    private String[] managerPackages = new String[0];

    private final Shizuku.OnRequestPermissionResultListener permListener =
            (requestCode, grantResult) -> ui.post(this::refreshStatus);

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        statusView = findViewById(R.id.status);
        logView = findViewById(R.id.log);
        rootBtn = findViewById(R.id.root);
        shizukuBtn = findViewById(R.id.shizuku);
        rebootBtn = findViewById(R.id.reboot);
        shutdownBtn = findViewById(R.id.shutdown);
        softBootBtn = findViewById(R.id.soft_boot);
        openCheckerBtn = findViewById(R.id.open_checker);
        copyRunLogBtn = findViewById(R.id.copy_run_log);
        clearRunLogBtn = findViewById(R.id.clear_run_log);
        pkgEdit = findViewById(R.id.pkg);
        managerSpinner = findViewById(R.id.manager_spinner);
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setTextIsSelectable(false);

        prefs = getSharedPreferences("cfg", MODE_PRIVATE);
        Notifier.ensureChannel(this);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
        setupManagerChoices();
        ArrayAdapter<String> managerAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_dropdown_item, managerLabels);
        managerSpinner.setAdapter(managerAdapter);
        selectManager(prefs.getString("ksu_pkg", detectManagerPackage()));
        managerSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, android.view.View view,
                                       int position, long id) {
                boolean custom = position == managerPackages.length - 1;
                pkgEdit.setEnabled(custom);
                if (!custom) {
                    pkgEdit.setText(managerPackages[position]);
                }
            }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) {
            }
        });

        Shizuku.addRequestPermissionResultListener(permListener);
        rootBtn.setOnClickListener(v -> startRoot());
        shizukuBtn.setOnClickListener(v -> requestShizuku());
        copyRunLogBtn.setOnClickListener(v -> copyLog());
        clearRunLogBtn.setOnClickListener(v -> clearLog());
        rebootBtn.setOnClickListener(v -> rebootDevice());
        shutdownBtn.setOnClickListener(v -> shutdownDevice());
        softBootBtn.setOnClickListener(v -> softRebootDevice());
        openCheckerBtn.setOnClickListener(v -> {
            Intent intent = new Intent(this, BootimgCheckerActivity.class);
            startActivity(intent);
        });

        refreshStatus();
        if (deviceStatus() != 0) {
            appendLog("注意：本机版本不在已验证列表（适配目标是 avr / XT2611，"
                    + "版本 W3WWL36.65-48-7 或 A171WWH.42-35-16）。执行可能失败"
                    + "甚至把内核搞崩 —— 风险自负。");
        }
        int km = kernelMatch();
        if (km == 1) {
            appendLog("⚠ 内核不匹配：载荷是按 " + expectedKernel()
                    + " 编译的，而本机运行的是 " + kernelVersion()
                    + "。偏移对不上，请勿执行 —— 先提取该版本的偏移"
                    + "（见 exploit/src/devices）。");
        } else if (km == 0) {
            appendLog("内核与载荷偏移匹配（" + kernelVersion() + "）");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
        checkRootedAsync();
        ui.postDelayed(this::refreshStatus, 500);
        ui.postDelayed(this::refreshStatus, 1500);
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permListener);
        super.onDestroy();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // Notification click brings the existing instance to front; don't recreate.
        setIntent(intent);
    }

    /** Boot-time kernel release from the read-only property (KSU can't spoof it). */
    private String readSystemProperty(String key) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            Method get = cls.getMethod("get", String.class);
            Object result = get.invoke(null, key);
            return result == null ? null : result.toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Kernel release from /proc/version ("Linux version <release> (...)" ). */
    private String readProcVersion() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/version"))) {
            String line = r.readLine();
            if (line != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 3) {
                    return parts[2];
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private String[] kernelCandidates() {
        return new String[]{
                readSystemProperty("ro.kernel.version"),
                System.getProperty("os.version", ""),
                readProcVersion(),
        };
    }

    private String kernelVersion() {
        // Prefer the most complete kernel version string (longest).
        String best = null;
        for (String v : kernelCandidates()) {
            if (v != null && !v.isEmpty()) {
                String t = v.trim();
                if (best == null || t.length() > best.length()) {
                    best = t;
                }
            }
        }
        return best != null ? best : "?";
    }

    /** 当前生效 payload 对应的内核串。 */
    private String expectedKernel() {
        return isA17Build() ? EXPECT_KERNEL_A17 : EXPECT_KERNEL_A16;
    }

    /** 是不是 Android 17 那条 build（A171WWH.42-35-16）。 */
    private boolean isA17Build() {
        for (String s : buildSources()) {
            if (s != null && s.contains("A171WWH")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 设备内核是否与 payload 的偏移匹配？
     * 0 = 匹配, 1 = 不匹配, 2 = 读不到。
     *
     * exploit 的 kallsyms 地址与 call-site 常量是编译期烧进 native payload 的，
     * 内核串对不上就意味着偏移对不上 —— 写会打偏，或者打到别处直接 panic。
     */
    private int kernelMatch() {
        String live = kernelVersion();
        String expected = expectedKernel();
        if (live.isEmpty() || live.equals("?")) {
            return 2;
        }
        return live.equals(expected) ? 0 : 1;
    }

    /** 0 = 已验证 build, 1 = avr 但 build 未验证, 2 = 非 avr 设备。 */
    private int deviceStatus() {
        if (!isAvrDevice()) {
            return 2;
        }
        return isVerifiedBuild() ? 0 : 1;
    }

    /** build id 是否在已适配列表里。 */
    private boolean isVerifiedBuild() {
        for (String want : EXPECT_BUILDS) {
            for (String s : buildSources()) {
                if (s != null && s.contains(want)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isAvrDevice() {
        return Build.DEVICE != null && Build.DEVICE.toLowerCase().contains("avr");
    }

    private String[] buildSources() {
        return new String[]{
                Build.DISPLAY,
                Build.ID,
                Build.FINGERPRINT,
                Build.VERSION.INCREMENTAL,
        };
    }

    /** 用于显示的 build 串（优先命中已适配 build id 的那个）。 */
    private String deviceBuild() {
        for (String want : EXPECT_BUILDS) {
            for (String s : buildSources()) {
                if (s != null && s.contains(want)) {
                    return s;
                }
            }
        }
        return Build.DISPLAY != null ? Build.DISPLAY : "?";
    }

    /** Fast app-side check; may be hidden by KernelSU's hide features. */
    private boolean isKsuLoaded() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/modules"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains("kernelsu") || line.contains("sukisu")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Reliable root detection through Shizuku: KSU hide features filter
     * /proc/modules for apps, but a shell-issued {@code su -c id} still tells
     * the truth. Runs off the UI thread.
     */
    private boolean detectRooted() {
        if (isKsuLoaded()) {
            return true;
        }
        try {
            if (!Shizuku.pingBinder()
                    || Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
            String out = RootRunner.runShizukuCommand("/system/bin/su -c id 2>&1");
            if (out != null && out.contains("uid=0")) {
                return true;
            }
            out = RootRunner.runShizukuCommand("su -c id 2>&1");
            if (out != null && out.contains("uid=0")) {
                return true;
            }
            out = RootRunner.runShizukuCommand("/data/adb/ksu/bin/su -c id 2>&1");
            if (out != null && out.contains("uid=0")) {
                return true;
            }
            String mods = RootRunner.runShizukuCommand(
                    "grep -i -E 'kernelsu|sukisu' /proc/modules 2>&1");
            return mods != null && (mods.contains("kernelsu") || mods.contains("sukisu"));
        } catch (Throwable t) {
            return false;
        }
    }

    private void checkRootedAsync() {
        if (rootChecking || running) {
            return;
        }
        rootChecking = true;
        new Thread(() -> {
            boolean r = detectRooted();
            ui.post(() -> {
                rooted = r;
                rootChecked = true;
                rootChecking = false;
                refreshStatus();
            });
        }).start();
    }

    private void refreshStatus() {
        String dev = android.os.Build.DEVICE;
        String build = deviceBuild();
        String kernel = kernelVersion();
        int st = deviceStatus();

        String shizuku;
        boolean shizukuReady = false;
        try {
            if (!Shizuku.pingBinder()) {
                shizuku = "Shizuku：未运行（先打开 Shizuku 再回来）";
            } else if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                shizuku = "Shizuku：就绪";
                shizukuReady = true;
            } else {
                shizuku = "Shizuku：未授权（点“申请授权”）";
            }
        } catch (Throwable t) {
            shizuku = "Shizuku：不可用 (" + t.getClass().getSimpleName() + ")";
        }

        String target = st == 0 ? "已验证机型 / 版本（avr / XT2611）"
                : st == 1 ? "试验态（avr，但版本不在适配列表）"
                : "不支持（非 avr 机型）";
        boolean ksuLoaded = isKsuLoaded();
        if (ksuLoaded) {
            rooted = true;
            rootChecked = true;
        }
        String rootState;
        if (!rootChecked) {
            rootState = "root：检查中…";
        } else {
            rootState = rooted ? "已 root（KernelSU 已加载）" : "未 root";
        }
        String payloadLine;
        int km = kernelMatch();
        if (km == 0) {
            payloadLine = "载荷     " + expectedKernel() + "\n"
                    + "          ✓ 内核与载荷偏移匹配";
        } else if (km == 1) {
            payloadLine = "载荷     " + expectedKernel() + "\n"
                    + "          ⚠ 内核不匹配 —— 载荷偏移是给另一个内核编的\n"
                    + "          本机内核 " + kernel + "（请勿执行）";
        } else {
            payloadLine = "载荷     " + expectedKernel() + "\n"
                    + "          ? 读不到设备内核版本";
        }

        statusView.setHorizontallyScrolling(false);
        statusView.setSingleLine(false);
        statusView.setText(
                target + "\n"
                        + "设备     " + dev + "\n"
                        + "适配机型 avr / XT2611\n"
                        + "版本     " + build + "\n"
                        + payloadLine + "\n"
                        + rootState + "\n"
                        + shizuku);
        shizukuBtn.setText(shizukuReady ? R.string.btn_shizuku_granted : R.string.btn_request_shizuku);
        rootBtn.setText(running ? R.string.btn_running : R.string.btn_root);
        rootBtn.setEnabled(shizukuReady && !running);
        rebootBtn.setEnabled(shizukuReady);
        shutdownBtn.setEnabled(shizukuReady);
        softBootBtn.setVisibility(rooted ? android.view.View.VISIBLE : android.view.View.GONE);
        softBootBtn.setEnabled(rooted && !running);
        copyRunLogBtn.setEnabled(logView.length() > 0);
    }

    private boolean packageInstalled(String packageName) {
        try {
            getPackageManager().getApplicationInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private void setupManagerChoices() {
        java.util.Set<String> installed = installedPackages();
        ArrayList<String> labels = new ArrayList<>();
        ArrayList<String> packages = new ArrayList<>();
        addManagerIfInstalled(labels, packages, installed, CURRENT_SPOOF, "KernelSU Next（已改名）");
        addManagerIfInstalled(labels, packages, installed, "me.weishu.kernelsu", "KernelSU（原版）");
        addManagerIfInstalled(labels, packages, installed, "com.rifsxd.ksunext", "KernelSU Next（原版）");
        addManagerIfInstalled(labels, packages, installed, "com.sukisu.ultra", "SukiSU Ultra");
        addManagerIfInstalled(labels, packages, installed, "com.resukisu.resukisu", "ReSukiSU");
        // Any other installed package whose name looks like a KSU manager.
        for (String p : installed) {
            String low = p.toLowerCase();
            if ((low.contains("kernelsu") || low.contains("sukisu") || low.contains("ksunext"))
                    && !packages.contains(p)) {
                labels.add(p);
                packages.add(p);
            }
        }
        appendLog("检测到的管理器: " + packages);
        labels.add("自定义包名");
        packages.add("");
        managerLabels = labels.toArray(new String[0]);
        managerPackages = packages.toArray(new String[0]);
    }

    private java.util.Set<String> installedPackages() {
        java.util.Set<String> set = new java.util.HashSet<>();
        try {
            for (android.content.pm.PackageInfo pi : getPackageManager().getInstalledPackages(0)) {
                set.add(pi.packageName);
            }
        } catch (Throwable ignored) {
        }
        return set;
    }

    private void addManagerIfInstalled(ArrayList<String> labels, ArrayList<String> packages,
                                       java.util.Set<String> installed,
                                       String packageName, String label) {
        if (installed.contains(packageName)) {
            labels.add(label);
            packages.add(packageName);
        }
    }

    private String detectManagerPackage() {
        for (String packageName : managerPackages) {
            if (!packageName.isEmpty() && packageInstalled(packageName)) {
                return packageName;
            }
        }
        return CURRENT_SPOOF;
    }

    private void selectManager(String packageName) {
        for (int i = 0; i < managerPackages.length - 1; i++) {
            if (managerPackages[i].equals(packageName)) {
                managerSpinner.setSelection(i);
                pkgEdit.setEnabled(false);
                pkgEdit.setText(packageName);
                return;
            }
        }
        managerSpinner.setSelection(managerPackages.length - 1);
        pkgEdit.setEnabled(true);
        pkgEdit.setText(packageName);
    }

    private void requestShizuku() {
        try {
            if (!Shizuku.pingBinder()) {
                toast("请先启动 Shizuku，再回到本页");
                try {
                    android.content.Intent intent = getPackageManager().getLaunchIntentForPackage(
                            "moe.shizuku.privileged.api");
                    if (intent != null) {
                        startActivity(intent);
                    }
                } catch (Throwable ignored) {
                }
                return;
            }
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(0);
                ui.postDelayed(this::refreshStatus, 500);
                ui.postDelayed(this::refreshStatus, 1500);
            } else {
                toast("Shizuku 权限已授予");
                refreshStatus();
            }
        } catch (Throwable t) {
            toast("Shizuku 异常：" + t.getClass().getSimpleName());
        }
    }

    private void startRoot() {
        if (running) {
            return;
        }
        if (rooted) {
            new AlertDialog.Builder(this)
                    .setTitle("已经 root 了")
                    .setMessage("KernelSU 已加载。重复执行通常没必要，"
                            + "还可能把内核搞崩。仍要继续吗？")
                    .setPositiveButton("继续", (d, w) -> runRoot())
                    .setNegativeButton("取消", null)
                    .show();
            return;
        }
        runRoot();
    }

    private void runRoot() {
        if (running) {
            return;
        }
        String pkg = pkgEdit.getText().toString().trim();
        if (pkg.isEmpty()) {
            toast("请先选择或填写 KernelSU 系管理器的包名");
            return;
        }
        // Package names are only [a-zA-Z0-9.]. Reject anything else up front so
        // the value can never be interpolated into a shell command as code.
        if (!pkg.matches("[a-zA-Z0-9.]+")) {
            toast("包名不合法：" + pkg);
            return;
        }
        if (!packageInstalled(pkg)) {
            new AlertDialog.Builder(this)
                    .setTitle("管理器未安装")
                    .setMessage("'" + pkg + "' 未安装。请先安装 KernelSU 系的管理器"
                            + "（KernelSU / KernelSU-Next / SukiSU / ReSukiSU），"
                            + "或在上方重新选择。")
                    .setPositiveButton("确定", null)
                    .show();
            return;
        }
        try {
            if (!Shizuku.pingBinder()
                    || Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                toast("请先授予 Shizuku 权限");
                return;
            }
        } catch (Throwable t) {
            toast("Shizuku 异常：" + t);
            return;
        }

        prefs.edit().putString("ksu_pkg", pkg).apply();

        running = true;
        rootBtn.setEnabled(false);
        rootBtn.setText(R.string.btn_running);
        appendLog("=== 开始 · KSU 包名: " + pkg + " ===");

        final String finalPkg = pkg;
        new Thread(new RootRunner(this, finalPkg, new RootRunner.Sink() {
            @Override
            public void onLine(String line) {
                ui.post(() -> appendLog(line));
            }

            @Override
            public void onDone(boolean ok, String summary) {
                Notifier.notify(MainActivity.this,
                        ok ? "AvrRoot：已 root" : "AvrRoot：失败",
                        ok ? summary : summary + " 请重启后重试。",
                        Notifier.ID_AUTO);
                ui.post(() -> {
                    appendLog(summary);
                    if (ok) {
                        rooted = true;
                        rootChecked = true;
                    }
                    running = false;
                    rootBtn.setEnabled(true);
                    refreshStatus();
                });
            }
        })).start();
    }

    private void appendLog(String s) {
        logView.append(s + "\n");
        copyRunLogBtn.setEnabled(logView.length() > 0);
    }

    private void copyLog() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("AvrRoot 日志", logView.getText()));
        toast("日志已复制");
    }

    private void clearLog() {
        logView.setText("");
        copyRunLogBtn.setEnabled(false);
    }

    private void rebootDevice() {
        issuePowerCommand("svc power reboot 2>&1 || setprop sys.powerctl reboot 2>&1",
                "重启", "正在重启…", "reboot");
    }

    private void shutdownDevice() {
        // 部分国产 ROM 把 `svc power shutdown` 映射成“快速关机”（关完立刻重启），
        // 这里改成直接切 init 的 powerctl（等同长按电源键关机）；
        // 需要 root，所以先试 setprop，不行再 reboot -p。
        issuePowerCommand(
                "/system/bin/su -c 'setprop sys.powerctl shutdown' 2>&1 "
                        + "|| /system/bin/su -c 'reboot -p' 2>&1",
                "关机", "正在关机…", "shutdown");
    }

    private void softRebootDevice() {
        if (!rooted) {
            toast("请先提权，再用软重启");
            return;
        }
        // This ROM doesn't support userspace reboot, so hand off to the
        // KernelSU manager, whose soft-reboot option is known to work.
        String pkg = pkgEdit.getText().toString().trim();
        if (pkg.isEmpty()) {
            pkg = "me.weishu.kernelsu";
        }
        try {
            android.content.Intent intent = getPackageManager().getLaunchIntentForPackage(pkg);
            if (intent != null) {
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                appendLog("已打开管理器（" + pkg + "）—— 用它的软重启");
            } else {
                toast("找不到管理器：" + pkg);
            }
        } catch (Throwable t) {
            toast("无法打开管理器：" + t.getClass().getSimpleName());
        }
    }

    private void issuePowerCommand(String command, String action, String toastMsg, String logLabel) {
        try {
            if (!Shizuku.pingBinder()
                    || Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                toast("请先授予 Shizuku 权限");
                return;
            }
        } catch (Throwable t) {
            toast("Shizuku 异常：" + t.getClass().getSimpleName());
            return;
        }
        toast(toastMsg);
        appendLog("--- 已请求" + logLabel + " ---");
        new Thread(() -> {
            String out = RootRunner.runShizukuCommand(command);
            String o = out == null ? "" : out.trim();
            ui.post(() -> {
                if (!o.isEmpty()) {
                    appendLog(o);
                }
                if (o.contains("SecurityException") || o.contains("denied")
                        || o.contains("Permission") || o.contains("not permitted")
                        || o.contains("not found") || o.contains("No such file")) {
                    appendLog(action + " didn't run (needs root or is blocked). "
                            + "Do it manually or root first.");
                    toast(action + " needs root / blocked — do it manually");
                }
            });
        }).start();
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
