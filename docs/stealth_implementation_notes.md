# Runtime Stealth 实现盘点（按 `*_stealth` 组件拆分）

## 1. 范围与入口

本盘点覆盖项目中“隐匿能力”相关实现，并按组件域拆分：

- `inject_stealth`：注入后隐匿（`solist` + `remap` + 端口语义入口）
- `tracer_stealth`：tracer 使用的 `procfs` 路径规则与 maps 快照净化
- `syscall_handler`：seccomp/ptrace 事件驱动编排与缓冲区改写执行

主要入口链路：

1. `runtime/injector.cpp` 调用注入流程（`inject_lib`）
2. `inject.cpp` 在每次注入成功后调用 `inject_stealth::post_library_load_hide(...)`
3. tracer 在 `syscall_handler.cpp` 中调用 `tracer_stealth::*` 做路径识别与 maps 快照构建

## 2. 能力矩阵（现状）

| 能力 | 代码位置 | 触发时机 | 当前状态 |
|---|---|---|---|
| `solist` 摘链 | `module/src/jni/inject_stealth.cpp` + `module/src/jni/solist_patch.cpp` | 每次 `inject_lib` 成功后 | 已生效 |
| 内存重映射 | `module/src/jni/inject_stealth.cpp` + `module/src/jni/remapper.cpp` | 每次 `inject_lib` 成功后 | 已生效（实现有稳定性风险） |
| `/proc/*/maps` 篡改 | `module/src/jni/tracer/tracer_stealth.cpp` + `module/src/jni/tracer/syscall_handler.cpp` | tracer 模式下命中相关 syscall | 已生效 |
| `/proc/*/status` TracerPid 篡改 | `module/src/jni/tracer/tracer_stealth.cpp` + `module/src/jni/tracer/syscall_handler.cpp` | tracer 模式下命中相关 syscall | 已生效 |
| 隐藏端口选择（日志） | `module/src/jni/inject_stealth.cpp` | 注入流水线开始阶段 | 已生效（仅日志语义） |

## 3. 实现细节

### 3.1 注入域 stealth（`inject_stealth`）

实现文件：

- `module/src/jni/inject_stealth.h`
- `module/src/jni/inject_stealth.cpp`

核心逻辑：

- `post_library_load_hide(load_base, lib_path, log_context)`
  - `solist_remove_lib(load_base)`：从 linker `solist` 链表摘除
  - `remap_lib(lib_path)`：重映射目标库映射段，降低 maps 关联性
- `choose_hidden_port(cfg)`：根据 `gadget_interaction` 与端口配置决定“隐藏端口语义”
- `log_hidden_port_for_config(cfg)`：输出端口隐藏语义日志（当前不做 `/proc/net/tcp` 篡改）

调用点：

- `module/src/jni/inject.cpp` 的 `inject_lib()` 成功分支（`xdl_open` / `dlopen`）
- `module/src/jni/runtime/injector.cpp` 的流水线启动阶段（端口日志）

### 3.2 `solist` 隐匿实现（`solist_patch.cpp`）

实现文件：`module/src/jni/solist_patch.cpp`

核心逻辑：

- `solist_remove_lib(load_address)` 通过 `xdl_open` 打开 linker（APEX 路径优先，失败回退 `/system/bin/linker*`）
- 解析 linker 私有符号：
  - `__dl__ZL6solist`
  - `__dl__ZL6sonext`
- 使用 `find_soinfo_offsets()` 动态探测 `soinfo` 中 `base` 和 `next` 偏移
- 遍历 `solist` 找到 `base == load_address` 节点后断链
- 若删的是尾节点则同步更新 `sonext`

### 3.3 重映射隐匿实现（`remapper.cpp`）

实现文件：`module/src/jni/remapper.cpp`

核心逻辑：

- `get_modules_by_name()` 扫描 `/proc/self/maps`，按 basename 匹配段
- `remap_lib(lib_path)` 对每个命中段执行：
  - 匿名 `mmap(PROT_WRITE)` 新区域
  - 必要时对原段 `mprotect(PROT_READ)`
  - `memmove` 拷贝原段内容到新区域
  - `mremap(..., MREMAP_FIXED, original_start)` 覆盖回原地址
  - 按原权限 `mprotect` 恢复

已识别风险：

- `PROCMAPSINFO` 内 `dev/path` 保存了局部栈数组地址（悬垂指针）
- `mmap` 失败判断使用 `map == nullptr`，应使用 `MAP_FAILED`
- `mremap` 返回值未检查

### 3.4 Tracer 域 stealth（`tracer_stealth` + `syscall_handler`）

实现文件：

- `module/src/jni/tracer/tracer_stealth.h`
- `module/src/jni/tracer/tracer_stealth.cpp`
- `module/src/jni/tracer/syscall_handler.cpp`

`tracer_stealth` 职责：

- `is_proc_status_path(...)`：识别 status 访问路径（含 `self/thread-self` 与目标 pid/tid 语义）
- `is_proc_maps_path(...)`：识别 maps 访问路径
- `build_sanitized_maps_snapshot(...)`：构建净化后的 maps 快照（`r-xp -> r--p`）

`syscall_handler` 职责：

- `tracked_fd_key{tgid, fd}`：跨线程统一 fd 归属
- `g_maps_fds` / `g_status_fds`：追踪 maps/status fd
- `g_maps_fd_states`：maps 流式改写状态（`stream_pos` / `sanitized_maps` / `tamper_enabled`）
- `tamper_maps_read_stream()`：流式 read 改写（兼容 1 字节读取）
- `tamper_tracer_pid()`：把 `TracerPid:\tN` 改为 `TracerPid:\t0`

处理流程（entry/exit 两阶段）：

1. `openat` entry：识别感兴趣路径并请求 `WAIT_EXIT`
2. `openat` exit：拿到 fd 后放入 `g_maps_fds/g_status_fds`
3. `read/pread64` entry：命中追踪 fd 时请求 `WAIT_EXIT`
4. `read/pread64` exit：执行 `maps` 或 `status` 缓冲区改写
5. `close` exit：清理相关 fd 状态

### 3.5 端口隐藏能力现状

当前仅保留“端口隐藏语义入口”：

- `inject_stealth::choose_hidden_port()`
- `inject_stealth::log_hidden_port_for_config()`

当前没有 `/proc/net/tcp` 拦截与篡改逻辑；后续如需恢复，建议仍挂在 `inject_stealth` 组件内实现。

## 4. 后续拆分建议（保持组件域语义）

1. `inject_stealth` 继续承接“注入后/注入阶段”隐匿能力
2. `tracer_stealth` 继续承接“tracer 域规则与净化算法”
3. `syscall_handler` 保持“事件编排 + 状态机 + ptrace 读写”职责，避免混入规则细节

## 5. 当前优先修复项

1. 修复 `remapper.cpp` 的悬垂指针与系统调用返回值检查
2. 将 `g_protected_libs` 从硬编码迁移到配置（当前在 `syscall_handler_init` 内固定写死）
3. 若恢复 net stealth，直接在 `inject_stealth` 内补齐 hook 生命周期，不再回退到 `inject.cpp` 大杂烩

## 6. 关键代码索引

- 注入域 stealth：`module/src/jni/inject_stealth.cpp`
- 注入流程调用点：`module/src/jni/inject.cpp`
- linker 摘链：`module/src/jni/solist_patch.cpp`
- 映射重排：`module/src/jni/remapper.cpp`
- tracer stealth 规则：`module/src/jni/tracer/tracer_stealth.cpp`
- maps/status 改写主逻辑：`module/src/jni/tracer/syscall_handler.cpp`
- tracer syscall 规则：`module/src/jni/tracer/syscall_rules.cpp`
