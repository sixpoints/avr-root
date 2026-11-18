package com.avrroot;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;

public class BootimgCheckerActivity extends Activity {

    private static final int PICK_BOOTIMG_REQUEST = 4201;

    private Button pickBtn;
    private Button closeBtn;
    private Button copyLogBtn;
    private Button clearLogBtn;
    private ProgressBar progress;
    private TextView statusView;
    private TextView logView;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean checking = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bootimg_checker);

        pickBtn = findViewById(R.id.pick_bootimg);
        closeBtn = findViewById(R.id.close_btn);
        copyLogBtn = findViewById(R.id.copy_check_log);
        clearLogBtn = findViewById(R.id.clear_check_log);
        progress = findViewById(R.id.check_progress);
        statusView = findViewById(R.id.check_status);
        logView = findViewById(R.id.check_log);

        pickBtn.setOnClickListener(v -> pickBootimg());
        closeBtn.setOnClickListener(v -> finish());
        copyLogBtn.setOnClickListener(v -> copyLog());
        clearLogBtn.setOnClickListener(v -> clearLog());
    }

    private void copyLog() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("Boot Image Check log", logView.getText()));
        toast("日志已复制");
    }

    private void clearLog() {
        logView.setText("");
    }

    private void pickBootimg() {
        if (checking) return;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        String[] mimeTypes = {"application/octet-stream"};
        intent.putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes);
        startActivityForResult(intent, PICK_BOOTIMG_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_BOOTIMG_REQUEST && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                checkBootimg(uri);
            }
        }
    }

    private void checkBootimg(Uri uri) {
        if (checking) return;
        checking = true;
        ui.post(() -> {
            pickBtn.setEnabled(false);
            progress.setVisibility(android.view.View.VISIBLE);
            progress.setProgress(0);
            statusView.setVisibility(android.view.View.VISIBLE);
            statusView.setText("准备中…");
            logView.setText("");  // clear log on new selection
        });
        String fileName = uri.getLastPathSegment();
        appendLog("=== 开始检查 boot.img ===");
        appendLog("文件：" + (fileName != null ? fileName : "(未知)"));

        new Thread(() -> {
            try {
                updateProgress(10, "Reading boot.img header…");
                // Copy URI content to a temp file we can random-access
                String tempPath = getCacheDir().getAbsolutePath() + "/bootimg_check_" + System.currentTimeMillis() + ".img";
                try (InputStream in = getContentResolver().openInputStream(uri);
                     java.io.FileOutputStream out = new java.io.FileOutputStream(tempPath)) {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                }

                updateProgress(30, "Verifying boot.img header…");
                // Parse header
                try (FileInputStream fis = new FileInputStream(tempPath)) {
                    byte[] hdr = new byte[4096];
                    fis.read(hdr);
                    if (!java.util.Arrays.equals(java.util.Arrays.copyOfRange(hdr, 0, 8), "ANDROID!".getBytes())) {
                        throw new IOException("Not a valid boot.img (missing ANDROID! magic)");
                    }
                    int kernelSize = readU32(hdr, 8);
                    int pageSize = readU32(hdr, 36);
                    if (pageSize == 0) pageSize = 4096;
                    int kernelOff = pageSize;
                    if (kernelSize <= 0 || kernelSize > 200_000_000) {
                        throw new IOException("内核尺寸异常：" + kernelSize);
                    }
                    appendLog("kernel_size=" + kernelSize + " page_size=" + pageSize);

                    updateProgress(50, "Extracting kernel payload…");
                    // Read kernel payload
                    byte[] kernel = new byte[kernelSize];
                    fis.getChannel().position(kernelOff);
                    int read = 0;
                    while (read < kernelSize) {
                        int n = fis.read(kernel, read, kernelSize - read);
                        if (n <= 0) throw new IOException("Unexpected EOF reading kernel");
                        read += n;
                    }

                    // Decompress if needed
                    if (kernel.length >= 2 && kernel[0] == 0x1f && kernel[1] == 0x8b) {
                        updateProgress(60, "Decompressing gzip kernel…");
                        kernel = decompressGzip(kernel);
                        appendLog("gzip 解压 → " + kernel.length + " 字节");
                    } else if (kernel.length >= 6
                            && kernel[0] == (byte)0xfd && kernel[1] == '7' && kernel[2] == 'z'
                            && kernel[3] == 'X' && kernel[4] == 'Z' && kernel[5] == 0) {
                        updateProgress(60, "Decompressing xz kernel…");
                        kernel = decompressXz(kernel);
                        appendLog("xz 解压 → " + kernel.length + " 字节");
                    } else {
                        appendLog("未压缩 Image（magic " + String.format("%02x%02x", kernel[0] & 0xff, kernel[1] & 0xff) + ")");
                    }
                    // Extract kernel version string from the image
                    String kver = extractKernelVersion(kernel);
                    if (kver != null) {
                        appendLog("kernel_version=" + kver);
                    }

                    updateProgress(80, "Checking call-site offsets…");
                    // 两组 avr call-site 都试：A16 (W3WWL36.65-48-7) 与 A17 (A171WWH.42-35-16)
                    boolean ok1_a16 = checkCallSite(kernel, 0xffffffc0805180a4L, "do_timer_create (avr A16)");
                    boolean ok2_a16 = checkCallSite(kernel, 0xffffffc080156c70L, "copy_process (avr A16)");

                    boolean ok1_a17 = checkCallSite(kernel, 0xffffffc080517744L, "do_timer_create (avr A17)");
                    boolean ok2_a17 = checkCallSite(kernel, 0xffffffc0801d7440L, "copy_process (avr A17)");

                    boolean ok_a16 = ok1_a16 && ok2_a16;
                    boolean ok_a17 = ok1_a17 && ok2_a17;

                    updateProgress(100, "Done");
                    ui.post(() -> {
                        if (ok_a16 || ok_a17) {
                            String type = ok_a17 ? "A17 (A171WWH.42-35-16)"
                                                 : "A16 (W3WWL36.65-48-7)";
                            statusView.setText("✓ 通过 — " + type);
                            appendLog("结果：✓ 通过 — " + type + " 的 call site 与 exploit 偏移一致");
                        } else {
                            statusView.setText("✗ 失败 — 偏移不匹配");
                            appendLog("结果：✗ 失败 — call site 不匹配（需要重新提取偏移）");
                        }
                    });
                }
            } catch (Throwable t) {
                ui.post(() -> {
                    statusView.setText("错误：" + t.getMessage());
                    appendLog("错误：" + t);
                });
            } finally {
                checking = false;
                ui.post(() -> {
                    pickBtn.setEnabled(true);
                    progress.setVisibility(android.view.View.GONE);
                });
            }
        }).start();
    }

    private void updateProgress(int progressValue, String status) {
        ui.post(() -> {
            progress.setProgress(progressValue);
            statusView.setText(status);
        });
    }

    private void appendLog(String s) {
        ui.post(() -> logView.append(s + "\n"));
    }

    private int readU32(byte[] data, int off) {
        return ((data[off] & 0xff) |
                ((data[off+1] & 0xff) << 8) |
                ((data[off+2] & 0xff) << 16) |
                ((data[off+3] & 0xff) << 24));
    }

    private boolean checkCallSite(byte[] kernel, long retVaddr, String name) {
        final long RELATIVE_BASE = 0xffffffc080000000L;
        long fileOff = retVaddr - RELATIVE_BASE;
        long blFile = fileOff - 4;
        if (blFile < 0 || blFile + 4 > kernel.length) {
            appendLog("[" + name + "] 超出范围");
            return false;
        }
        int insn = readU32(kernel, (int)blFile);
        // bl encoding: top 6 bits = 0b100101 (0x25). Use >>> (unsigned).
        if ((insn >>> 26) != 0x25) {
            appendLog("[" + name + "] 此处不是 BL 指令，偏移 " + Long.toHexString(blFile) + ": " + String.format("%08x", insn));
            return false;
        }
        int imm26 = insn & 0x3ffffff;
        if ((imm26 & 0x2000000) != 0) imm26 -= 0x4000000;
        long blVaddr = retVaddr - 4;
        long target = blVaddr + (imm26 << 2);
        boolean ok = (0xffffffc000000000L <= target && target <= 0xffffffff00000000L);
        appendLog("[" + name + "] BL 位于 " + Long.toHexString(blVaddr)
                + " -> target " + Long.toHexString(target) + " " + (ok ? "正常" : "异常"));
        return ok;
    }

    private byte[] decompressGzip(byte[] data) throws IOException {
        java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(data);
        java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(bis);
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int len;
        while ((len = gis.read(buf)) > 0) {
            bos.write(buf, 0, len);
        }
        gis.close();
        return bos.toByteArray();
    }

    private byte[] decompressXz(byte[] data) throws IOException {
        throw new IOException("XZ decompression not implemented (not needed for avr)");
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    /**
     * Extract the Linux version string from a raw arm64 kernel Image.
     * The string "Linux version " appears in the kernel's banner.
     */
    private String extractKernelVersion(byte[] kernel) {
        String needle = "Linux version ";
        byte[] needleBytes = needle.getBytes();
        for (int i = 0; i < kernel.length - needleBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < needleBytes.length; j++) {
                if (kernel[i + j] != needleBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                int end = i + needleBytes.length;
                while (end < kernel.length && kernel[end] != '\n' && kernel[end] != '\0') {
                    end++;
                }
                return new String(kernel, i, end - i, java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
