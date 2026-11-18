# AvrRoot

一键 **临时 root**，面向 **联想拯救者手机 Y70 新一代 / moto edge 70 max**
（`XT2611-1` / `XT2611-2`，codename **`avr`**，SM8845）。

基于 [CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)（POSIX CPU timer UAF），
移植自 [Dream-Rainy/CVE-2026-98260](https://github.com/Dream-Rainy/CVE-2026-98260) 与
[cramqin/pudding-root](https://github.com/cramqin/pudding-root)。

> **临时 root**：只存在于当前这一次开机，**重启即消失**。不解锁 bootloader、不修改任何分区、
> 重启后 Play Integrity 恢复正常。

---

## 支持的 build

内核串必须**完全一致**（`uname -r`），否则应用会拒绝运行 —— exploit 的 kallsyms 地址
与 call-site 常量是编译期烧进 payload 的，对不上就会写偏甚至 panic。

| payload | build id | Android | kernel release |
|---------|----------|---------|----------------|
| `libtimer-a16.so` | `W3WWL36.65-48-7` | 16 | `6.12.58-android16-6-gb0a9599c6c01-ab14987696-4k` |
| `libtimer-a17.so` | `A171WWH.42-35-16` | 17 | `6.12.58-android16-6-g09eda8c8505a-ab15950084-4k` |

两个 build 的偏移完全不同（kallsyms、`do_timer_create` / `copy_process` 的 call-site 都变了），
应用按 `Build.ID` 自动选 payload。

### 这套偏移是怎么来的

全部从本机 `boot.img` 推导，没有照抄别的机型（规则见上游 README §7.3）：

| 常量 | 来源 |
|------|------|
| `STATIC_TIMER_SITE` / `TIMER_SITE_LOW21` | `do_timer_create` 里 `bl kmem_cache_alloc_noprof` 的返回地址（前置 `adrp`/`ldr` 已核对指向 `posix_timers_cache`，`w1=0xdc0`） |
| `COPY_PROCESS_LOW21` | `copy_process`（`dup_task_struct`）里 `bl kmem_cache_alloc_node_noprof` 的返回地址（已核对指向 `task_struct_cachep`） |
| `*_STATIC` | 同一镜像的 kallsyms |
| `cred` / `task_struct` / `k_itimer` 结构常量 | 同一镜像的内嵌 BTF（`cred=0xb8`、`task_struct.cred=0x900`、`k_itimer=0x100`，与 6.12 GKI 一致） |
| `TASK_ALLOC_BYTES` | 未实测，初值 `0x1840`；`scan_task_allocs()` 接受 `0x1440/0x1640/0x1840` |

---

## ⚠️ 先查前置条件（不满足就别装）

这个 exploit 依赖 **tracefs** 与 `/proc/slabinfo` 的可读性。**不满足就跑不起来**，
不是复现步骤的问题。

Windows `cmd` 下**不要**用单引号包命令（`adb shell 'cat ...'` 会把整串当成一条命令名，
报 `...: inaccessible or not found`，那是"命令没跑起来"，不是"权限不足"）：

```bat
adb shell id
adb shell cat /proc/sys/kernel/perf_event_paranoid
adb shell head -2 /proc/slabinfo
adb shell ls /sys/kernel/tracing/events/kmem/kmem_cache_alloc
```

PowerShell 同理，用双引号或直接不加引号。

| 项 | 期望 | A16 `W3WWL36.65-48-7` 实测 |
|----|------|------------------------------|
| `perf_event_paranoid` | `-1` | ✅ `-1` |
| `/proc/slabinfo` | 可读 | ✅ 可读 |
| `tracefs` 的 `kmem/kmem_cache_alloc` | 可见 | ✅ `enable filter format hist id trigger` |
| `trace_pipe` 可读 | shell 在 `readtracefs` 组 | ⚠️ 待确认（`adb shell id` 里要有 `readtracefs`） |

一键体检脚本：[`tools-scripts/avr-probe.bat`](tools-scripts/avr-probe.bat)（Windows cmd）
/ [`avr-probe.sh`](tools-scripts/avr-probe.sh)（WSL/Git Bash），全程只读。

若这几条不满足，本工具在你这台机器上无效。

---

## 界面语言

默认**中文**（`res/values/strings.xml`），英文机自动走 `res/values-en/strings.xml`。
所有静态文案都走 `@string/...`；运行时日志（`appendLog`）也是中文。
想改文案只改这两个文件，不用碰布局。

## 用法

1. 装一个自带 `libksud.so` 的 root 管理器（KernelSU / KernelSU-Next / SukiSU Ultra /
   ReSukiSU / BakaSU / KowSU）。
2. 装 `AvrRoot-<version>.apk`。
3. 打开应用，确认顶部状态是 `VERIFIED BUILD (avr / XT2611)`、且 `kernel matches payload offsets`。
4. 点 **执行**。跑的是 `timer fake -d`（伪造 cred + `ksud late-load`）。
5. 概率性成功：失败就重启再来。**不要**在同一个 boot 里重跑。

想先安全地验证移植是否对得上，可以用 `BootimgCheckerActivity`（应用内"检查 boot.img"）：
选一个本机的 `boot.img`，它会在两个 `bl` 位置校验指令编码。PASS 说明 call-site 常量正确。

---

## 构建

### CI（推荐）

push 到 `main` 就会触发 [`.github/workflows/build.yml`](.github/workflows/build.yml)：

1. 装 Android SDK + NDK
2. **用 NDK 重新编译两个 payload**（`exploit/build.sh`）→ `app/src/main/jniLibs/arm64-v8a/`
3. `./gradlew assembleRelease` 出 APK
4. 上传 artifact `AvrRoot-apk`，并在 push 时创建 prerelease

CI 还会产出 `AvrRoot-tools` artifact，里面有 `taskleak`（实测 `TASK_ALLOC_BYTES` 用）。

> 仓库里**不再提交**编译好的 `.so`。偏移是编译期常量，必须由 CI 从
> `exploit/src/devices/avr-cn-a16|a17/offsets.h` 现场编出来 —— 用别人机器编的 `.so`
> 会写错地址。

### 本地

```sh
# 需要 NDK r27+
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang \
TARGET=aarch64-linux-android31 bash exploit/build.sh

./gradlew assembleRelease     # 产物: app/build/outputs/apk/release/
```

`keystore.p12` 与默认口令沿用上游（`puddingroot`），所以连续构建可以覆盖安装。
**公开仓库前请换成自己的签名并改用 Secrets**。

---

## 致谢

- exploit 本体：[YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
- 设备移植与工程化：[Dream-Rainy/CVE-2026-98260](https://github.com/Dream-Rainy/CVE-2026-98260)
- Android 外壳 / CI：[cramqin/pudding-root](https://github.com/cramqin/pudding-root)
- 其他参考见 [`exploit/ATTRIBUTION.md`](exploit/ATTRIBUTION.md)

上游未声明许可证，本仓库同样不对派生代码主张任何许可证。

## 免责

见 [DISCLAIMER.md](DISCLAIMER.md)。只在你拥有的设备上使用；内核内存会被故意破坏，
失败可能 panic / 重启 / 数据丢失。
