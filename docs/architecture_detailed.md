# ZygiskFrida 架构详解（基于当前源码）

> 基线：`module.gradle` 中 `moduleVersion = v1.9.1`  
> 分析范围：`README.md`、Gradle/模板脚本、`module/src/jni/**`

## 1. 项目目标与核心能力

该项目在传统 “Zygisk 注入 Frida Gadget” 基础上，扩展为三阶段工作流：

1. `seccomp + ptrace` 观测与干预目标进程关键 syscall（探测）
2. 在 SO 加载窗口执行远程 patch（绕过/压制反调试）
3. 注入 Frida Gadget（调试）

对应源码主线：

- 注入与 Zygisk 入口：`module/src/jni/main_zygisk.cpp`、`module/src/jni/inject.cpp`
- 反检测 tracer：`module/src/jni/tracer/*`
- 隐匿增强：`module/src/jni/remapper.cpp`、`module/src/jni/solist_patch.cpp`

## 2. 代码结构与模块职责

### 2.1 顶层目录

- `module/`：Android 库模块，编译出 `libzygiskfrida.so`
- `template/magisk_module/`：Magisk 安装模板与脚本
- `gadget/`：构建时下载/准备的 Frida Gadget 二进制
- `docs/`：说明文档
- `scripts/`：逆向辅助脚本（如 `decode_libtprt_vm.py`）

### 2.2 Native 子模块（`module/src/jni`）

- `main_zygisk.cpp`：Zygisk 模块入口 + root companion handler + IPC 协议
- `main_riru.cpp`：Riru 兼容入口
- `runtime/zygisk_entry.{h,cpp}`：pre/post specialize 运行时入口编排
- `runtime/companion_client.{h,cpp}`：模块侧 companion IPC 客户端
- `runtime/injector.{h,cpp}`：等待/延迟/注入执行管线（支持延迟后准备阶段）
- `config.{h,cpp}`：高级/简单配置解析
- `inject.{h,cpp}`：注入主流程（等待初始化、延迟、加载库、清理）
- `child_gating.{h,cpp}`：fork/vfork 子进程门控（GOT patch）
- `remapper.{h,cpp}`：基于 `/proc/self/maps` 的内存重映射
- `solist_patch.{h,cpp}`：linker `solist` 链表摘除
- `tracer/*`：seccomp 注入、ptrace 事件循环、syscall 处理与内存篡改
- `xdl/*`：第三方动态链接辅助库（vendor）
- `zygisk.h`：Zygisk 公共 API 头（上游）

## 3. 构建、打包与安装架构

## 3.1 构建系统

- Gradle + AGP：顶层 `build.gradle`
- NDK 构建：`module/src/jni/Android.mk` + `Application.mk`
- Flavor：
  - `Zygisk`
  - `Riru`
- ABI：`armeabi-v7a`、`arm64-v8a`、`x86`、`x86_64`

`Android.mk` 会按 flavor 选择入口文件：

- `Zygisk` -> `main_zygisk.cpp`
- `Riru` -> `main_riru.cpp`

## 3.2 Gadget 来源策略

`module/build.gradle` 支持两种模式：

1. 在线下载 Frida release（默认）
2. `useLocalGadget=true` 使用 `local_gadget/` 本地 `.so`

## 3.3 Magisk 打包链路

`module/build.gradle` 在 `afterEvaluate` 中动态创建任务：

- `prepareMagiskFiles<Variant>`：组装模板、native lib、gadget、示例配置
- `zip<Variant>`：产出 zip 到 `out/`
- `push/flash/flashAndReboot<Variant>`：ADB 推送与刷入

关键处理：

- 将 `libzygiskfrida.so` 重命名为 ABI 名（如 `arm64-v8a.so`）
- 为每个文件生成 `.sha256sum`

## 3.4 安装脚本行为

`template/magisk_module/customize.sh` 负责：

- 提取并验证文件（依赖 `verify.sh`）
- 解压对应 ABI 的模块 so
- 解压/重命名 gadget 为：
  - `/data/adb/re.zyg.fri/libgadget.so`
  - `/data/adb/re.zyg.fri/libgadget32.so`（可选）
- 提取 `config.json.example` 到 `/data/adb/re.zyg.fri/`

## 4. 运行时进程与职责划分

## 4.1 三类进程

1. 目标 App 进程（被 Zygisk 注入模块代码）
2. Zygisk Companion 进程（root，处理文件复制/代理/tracer 拉起）
3. Tracer 子进程（root，`PTRACE_SEIZE` 监控目标线程组）

## 4.2 Zygisk 生命周期职责

### `preAppSpecialize`

位置：`main_zygisk.cpp`

- 读取包名
- `connectCompanion()` 建立 root IPC
- 发送包名并拉取完整 config JSON
- 立即请求启动 tracer（用于最早阶段监控/patch）
- 保留 companion 会话，供延迟后执行 SO 临时文件落地
- 可选请求 “abstract unix socket -> tcp” 代理（gadget connect 模式）

### `postAppSpecialize`

- 解析配置（优先 companion JSON）
- 启动 `runtime/injector` 异步管线
- 在 delay 结束后才执行：SO 临时文件落地 -> 写 gadget sidecar -> 注入 -> 清理

## 4.3 Companion handler 协议（`main_zygisk.cpp`）

协议为 length-prefixed 字符串 + 少量原始整数：

1. 模块发 `app_name`，companion 回配置 JSON（空字符串表示未命中）
2. 模块循环发 `lib_path`，companion 回 `tmp_path`；空字符串结束循环
3. 可选 unix proxy 请求（`on/off` + host/port/name）
4. 可选 tracer 请求（mode + pid + log + flags + so_hooks）

## 5. 配置系统实现细节

实现：`config.cpp`

配置优先级：

1. 高级配置 `config.json`（`targets[]`）
2. 兼容简单配置 `target_packages` + `injected_libraries`

关键字段（`target_config`）：

- 注入：`enabled`、`app_name`、`start_up_delay_ms`、`injected_libraries`
- 子进程门控：`child_gating.*`
- gadget 交互：`gadget_interaction`、`gadget_*`
- tracer：`tracer_mode`、`tracer_log_path`、`tracer_verbose_logs`、`tracer_block_self_kill`
- SO patch：`so_load_patches[]`（由 tracer 远程 patch 消费）

## 6. 注入主链路实现

实现：`inject.cpp`

流程：

1. `wait_for_init()`：轮询 `/proc/self/cmdline`，等待进程名稳定
2. 可选 `enable_child_gating()`
3. `delay_start_up()`
4. 遍历注入库，执行 `inject_lib()`

`inject_lib()` 细节：

- 优先 `xdl_open(..., XDL_TRY_FORCE_LOAD)`，失败回退 `dlopen`
- 成功后：
  - `solist_remove_lib(load_base)` 从 linker 链表隐藏
  - `remap_lib(lib_path)` 触发 maps 维度隐匿
  - 若路径含 `/.zyg_`，注入后 unlink `.so` 与 `.config.so`

## 7. 子模块实现细节

## 7.1 `child_gating`（`child_gating.cpp`）

核心不是 inline hook，而是 GOT patch：

- 解析每个已加载 ELF 的动态重定位表
- 定位 `fork`/`vfork` 的 GOT 槽位
- 改写为 `fork_replacement`

`fork_replacement` 的 3 种行为：

- `kill`：子进程直接退出
- `freeze`：子进程永久等待
- `inject`：子进程内再次执行库注入

## 7.2 `remapper`（`remapper.cpp`）

思路：扫描 `/proc/self/maps` 匹配目标库段，拷贝段内容到匿名映射，再 `mremap(MREMAP_FIXED)` 覆盖原地址，最后恢复权限。

用于降低基于文件映射关系的检测命中率。

## 7.3 `solist_patch`（`solist_patch.cpp`）

思路：

1. 用 `xdl` 打开 linker，解析 `__dl__ZL6solist` / `__dl__ZL6sonext`
2. 在 `soinfo` 中动态探测 `base` 与 `next` 字段偏移
3. 遍历链表找到 `base == load_address` 节点
4. 断链并在必要时更新 `sonext`

效果：`dl_iterate_phdr` / `dladdr` 难以枚举到目标库。

## 8. Tracer 子系统架构（重点）

## 8.1 入口与事件循环

`launch_tracer()` 在 companion 中 `fork` tracer 子进程，执行 `tracer_process()`。

`tracer_process()` 关键步骤：

1. `PTRACE_SEIZE` 目标 leader（无 `SIGSTOP`）
2. `PTRACE_INTERRUPT` 停住 leader
3. `freeze_all_threads()`：枚举并冻结线程组，消除 race window
4. 构建 seccomp BPF（`build_default_io_filter`）
5. `inject_seccomp_filter()` 注入（优先 TSYNC，失败则逐线程补注）
6. `syscall_handler_init()` 初始化日志与状态
7. 恢复线程运行，进入 `waitpid(__WALL)` 事件循环

## 8.2 seccomp 过滤策略（`seccomp_filter.cpp`）

默认关注 syscall：

- `openat`、`faccessat`、`newfstatat`、`readlinkat`、`statx`
- `getdents64`
- `read`/`pread64`/`close`
- `mmap`/`mprotect`
- 可选 kill 相关 syscall（由 `tracer_block_self_kill` 控制）

匹配返回 `SECCOMP_RET_TRACE`，其余 `ALLOW`。

## 8.3 远程注入 seccomp 机制（`seccomp_inject.cpp`）

核心机制：

- 读取并备份目标寄存器、栈、PC 处 8 字节代码
- 在目标 PC 写 `svc #0; brk #0` trampoline
- 远程执行：
  - `prctl(PR_SET_NO_NEW_PRIVS, 1)`
  - `seccomp(SECCOMP_SET_MODE_FILTER, flags, sock_fprog)`
- 恢复代码/栈/寄存器

支持：

- `SECCOMP_FILTER_FLAG_TSYNC` 一次同步
- TSYNC 失败后 leader + siblings 逐线程注入

## 8.4 syscall 处理器（`syscall_handler.cpp`）

分为两段处理：

1. `handle_seccomp_stop()`（syscall entry）
2. `handle_syscall_exit()`（对需要返回值/读缓冲区的 syscall 走 `PTRACE_SYSCALL`）

核心能力：

- `TracerPid` 隐藏：篡改 `/proc/*/status` 的 read 缓冲
- `/proc/maps` 伪装：将受保护库映射权限 `r-xp -> r--p`
- 自毁拦截：`exit_group/kill/tgkill...` 记录栈并可阻断
- SO load-time patch：
  - `openat` 跟踪目标 SO fd
  - `mmap` 记录 load bias
  - `mprotect(PROT_EXEC)` 出口触发 patch
  - 远程 `mprotect(RWX) -> POKEDATA -> mprotect(RX)` 写入指令

patch 支持两类：

- 固定返回：`MOV X0,#N; RET`
- 分支跳转：`B <branch_to>; NOP`

另外包含周期完整性校验，若 patch 漂移会尝试重写。

## 9. 文件与数据生命周期

## 9.1 安装后静态文件（默认）

- `/data/adb/re.zyg.fri/libgadget.so`
- `/data/adb/re.zyg.fri/libgadget32.so`（可选）
- `/data/adb/re.zyg.fri/config.json.example`
- 用户实际配置 `/data/adb/re.zyg.fri/config.json`

## 9.2 运行时临时文件

companion 将待注入库复制到：

- `/data/data/<pkg>/.zyg_<pid>_<counter>.so`

模块在 post 阶段创建：

- `/data/data/<pkg>/.zyg_<pid>_<counter>.config.so`

注入后 `inject_lib()` 尝试 unlink 这两类临时文件。

## 9.3 运行时日志

tracer 日志路径来自配置，默认：

- `/data/local/tmp/re.zyg.fri/syscall_trace.log`

## 10. 当前实现中的关键问题与重构切入点

以下条目均来自当前代码现状，适合作为整理优化优先级。

1. 文档/脚本/代码路径不一致  
- 代码主路径是 `/data/adb/re.zyg.fri`（`main_zygisk.cpp`）  
- 仍大量保留 `/data/local/tmp/re.zyg.fri`（README、配置样例、卸载脚本）

2. `postAppSpecialize` 回退仅查 `FALLBACK_DIR`  
- companion 配置缺失时只调用 `load_config(FALLBACK_DIR, app)`，未优先查 `MODULE_DIR`

3. `thread_disguise_name` 仅解析未消费  
- `config.cpp` 有字段校验，但注入链路无任何线程改名实现

4. `dobby_hook.cpp` 仍为遗留代码  
- 当前配置与主流程已统一使用 `so_load_patches`，不再由配置驱动 `setup_dobby_hooks()`

5. `inject.cpp` 中 `/proc/net/tcp` 过滤代码未生效  
- 定义了 `hook_open/hook_openat` 与 `real_open*`，但没有安装 hook 的路径

6. `remapper.cpp` 实现存在稳定性风险  
- `PROCMAPSINFO` 保存了局部栈数组指针  
- `mmap` 失败判断使用 `nullptr` 而非 `MAP_FAILED`  
- `mremap` 返回值未检查

7. 运行时策略注释与实际语义存在偏差  
- `tracer_mode` 注释提到 `block`，但实际 companion 请求只发送 `"probe"/"off"`

8. 卸载脚本路径过旧  
- `template/magisk_module/uninstall.sh` 仅删除 `/data/local/tmp/re.zyg.fri`

## 11. 建议的重构分层

建议将当前实现按职责拆成 5 层，降低耦合：

1. `runtime/zygisk_entry`：pre/post specialize + companion IPC 客户端  
2. `runtime/injector`：等待、延迟、库加载、临时文件清理  
3. `runtime/stealth`：solist/remap/maps/status/net 等隐匿能力  
4. `runtime/tracer`：seccomp 注入、事件循环、syscall 规则与 patch 引擎  
5. `config/`：schema、加载器、校验器（advanced/simple 兼容）

配套动作：

- 统一路径常量与 schema 文档
- `so_load_patches` 字段语义已收敛，可继续清理遗留 Dobby 代码
- 为 tracer 与 stealth 加最小回归测试（host 侧单测 + 设备侧 smoke test）
