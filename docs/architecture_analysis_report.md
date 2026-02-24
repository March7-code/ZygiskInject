# ZygiskFrida 架构与功能分析报告（当前代码基线）

> 版本基线：`moduleVersion = v1.9.1`（`module.gradle`）  
> 分析时间：2026-02-24  
> 分析范围：构建/打包、运行时架构、配置体系、功能点、主要风险与优化建议

---

## 1. 报告目标

本报告用于：

1. 盘点当前模块的**真实架构与功能边界**（以源码为准）；
2. 识别文档/配置/实现之间的偏差与技术债；
3. 给出后续“源码结构整理 + 配置体系优化”的可执行路线图。

---

## 2. 仓库结构总览

```text
ZygiskFrida-main/
├─ build.gradle / settings.gradle / gradle.properties
├─ module.gradle                      # 版本、模块元信息、fridaVersion
├─ config.json.example               # 安装后示例配置
├─ module/
│  ├─ build.gradle                   # Android+ndk-build、zip/push/flash任务
│  └─ src/jni/
│     ├─ main_zygisk.cpp             # Zygisk入口 + companion handler
│     ├─ main_riru.cpp               # Riru入口
│     ├─ inject.*                    # 注入主流程
│     ├─ config.*                    # 高级/简单配置解析
│     ├─ child_gating.*              # fork/vfork子进程门控
│     ├─ remapper.*                  # /proc/maps 重映射隐藏
│     ├─ solist_patch.*              # linker solist 隐藏
│     ├─ dobby_hook.*                # offset 级 inline hook（aarch64）
│     ├─ tracer/                     # seccomp+ptrace 反检测 tracer
│     └─ xdl/                        # 动态链接辅助库
├─ template/magisk_module/           # Magisk模板脚本
└─ docs/                             # 使用与设计文档
```

---

## 3. 构建与发布链路

### 3.1 构建系统

- 顶层：AGP `8.1.4`（`build.gradle`）
- NDK 固定：`25.2.9519653`（`module/build.gradle`）
- ABI：`armeabi-v7a / arm64-v8a / x86 / x86_64`（`module/src/jni/Application.mk`）
- 产品风味：`Zygisk` 与 `Riru`（`module/build.gradle`）

### 3.2 产物与任务

- 自动打包任务：`zipZygiskRelease/Debug`、`zipRiruRelease`；
- 设备操作任务：`push*`、`flash*`、`flashAndReboot*`；
- 最终 zip 在 `out/`，并生成逐文件 `sha256sum`。

### 3.3 Gadget来源策略

- 默认从 GitHub release 拉取 `frida-gadget-<ver>-android-<arch>.so.xz`；
- 支持 `useLocalGadget=true` 使用本地 `local_gadget/` 原始 `.so`。

---

## 4. 运行时架构（核心）

### 4.1 Zygisk双端模型（模块端 + companion端）

`main_zygisk.cpp`同时实现：

1. **Module端（App进程内）**：
   - `preAppSpecialize`：取包名、连 companion、拉配置、请求库复制、可选 unix proxy、可选 tracer 启动；
   - `postAppSpecialize`：解析配置、写 gadget `.config.so`、执行注入线程。

2. **Companion端（root）**：
   - 通过 `REGISTER_ZYGISK_COMPANION` 注册；
   - 接收 app_name，读取配置 JSON，按请求把库复制到 `/data/data/<pkg>/.zyg_*.so`；
   - 可创建 “abstract unix -> tcp” 代理；
   - arm64 下可拉起 tracer 子进程。

### 4.2 注入主链路

`check_and_inject_with_config` -> `inject_libs` -> `inject_lib`

- 时序：`wait_for_init` -> `child_gating`(可选) -> `delay_start_up` -> 遍历注入库；
- 加载优先：`xdl_open(...XDL_TRY_FORCE_LOAD)`，失败回退 `dlopen`；
- 成功后处理：
  1. `solist_remove_lib(load_base)`；
  2. `remap_lib(lib_path)`；
  3. 对临时 `.zyg_*.so` 与 `.config.so` 执行 unlink 清理。

### 4.3 Riru链路

`main_riru.cpp`采用传统 `forkAndSpecializePre/Post` 路径，仅调用 `check_and_inject(app_name)`，整体能力较 Zygisk 路径更“薄”。

---

## 5. 配置体系（源码实况）

### 5.1 解析入口

- `load_config(module_dir, app)`：优先高级 JSON，再回退简单配置文件；
- `parse_advanced_config(json, app)`：供 companion 传输 JSON 后在 app 进程复用解析。

### 5.2 高级配置字段（已实现）

- 基础：`app_name`、`enabled`、`start_up_delay_ms`、`injected_libraries`；
- 子进程门控：`child_gating.enabled/mode/injected_libraries`；
- Gadget交互：
  - `gadget_interaction`（listen/connect）
  - `gadget_listen_port`
  - `gadget_connect_address/port`
  - `gadget_connect_use_unix_proxy`
  - `gadget_connect_unix_name`
  - `gadget_on_load`
- tracer：`tracer_mode`、`tracer_log_path`、`tracer_verbose_logs`；
- 动态Hook：`dobby_hooks[]`（按 so 名 + offset + return_value）。

### 5.3 simple config 兼容

仍兼容 `target_packages` + `injected_libraries` 老方案。

---

## 6. 功能清单（按模块）

1. **按包名精准注入**（target级）；
2. **延迟注入**（启动窗口控制）；
3. **多库链式加载**；
4. **child gating**（freeze/kill/inject）；
5. **gadget connect模式 + unix proxy桥接**；
6. **solist隐藏**（对抗 `dl_iterate_phdr/dladdr`）；
7. **maps重映射隐藏**（路径维度）；
8. **arm64 tracer（probe）**：
   - seccomp过滤关心 syscall；
   - ptrace 监控 `/proc/*/status`（TracerPid置0）与 `/proc/*/maps`（x权限去除）等。
9. **aarch64 Dobby offset hook**（目标so加载后自动下钩）。

---

## 7. 关键问题与技术债（优先级）

## P0（建议优先处理）

1. **文档与实现严重错位**：
   - README/advanced_config 仍以 `/data/local/tmp/re.zyg.fri` 为主，而安装脚本当前落地目录是 `/data/adb/re.zyg.fri`（代码中也以 `/data/adb` 为主）；
   - 影响新用户配置成功率与运维成本。

2. **卸载脚本路径不一致**：
   - `template/magisk_module/uninstall.sh` 只删 `/data/local/tmp/re.zyg.fri`；
   - 当前安装主目录是 `/data/adb/re.zyg.fri`，存在残留风险。

3. **post阶段 fallback 路径可疑**：
   - `postAppSpecialize` companion失败后只 `load_config(FALLBACK_DIR, app)`，即仅查 `/data/local/tmp`，不查 `/data/adb`；
   - 一旦 companion不可用，可能出现“配置明明存在但无法命中”的隐性故障。

## P1（结构/可靠性问题）

4. **`thread_disguise_name` 仅解析未落地执行**：
   - 配置和文档均提及线程伪装，但当前代码无对应实现调用路径。

5. **`tracer_mode` 注释含 `block`，实际仅处理 `probe`**：
   - 配置语义与实现能力不一致，易误导使用者。

6. **`remapper.cpp` 存在实现级隐患**：
   - `PROCMAPSINFO` 中 `dev/path` 保存了局部数组指针，生命周期错误；
   - `mmap` 失败判断使用 `nullptr` 而非 `MAP_FAILED`；
   - `mremap` 返回值未检查。

7. **`/proc/net/tcp` 过滤逻辑未真正接入**：
   - `hook_open/openat` 函数存在，但当前路径中没有安装钩子的代码，功能名义存在、实际上未生效。

## P2（工程治理）

8. **配置 schema 缺少统一版本/校验层**：
   - 当前散落在 `deserialize_target_config` 中按字段“柔性”读取；
   - 长期演进会放大兼容难题。

9. **文档编码与维护状态不统一**：
   - `docs/build_and_test.md` 当前文本编码异常（终端显示乱码）；
   - 影响协作。

10. **`gradle.properties` 固定代理**：
    - 绑定 `127.0.0.1:7890`，在无代理环境会导致 gradle wrapper 拉取失败。

---

## 8. 结构整理建议（可执行路线）

### Phase 1：对齐与止血（1~2天）

1. 统一目录策略：`/data/adb/re.zyg.fri` 为主，`/data/local/tmp` 仅保留兼容说明；
2. 修复 `uninstall.sh` 路径清理；
3. 修复 `postAppSpecialize` fallback 逻辑（先 `/data/adb`，再 `/data/local/tmp`）；
4. 清理文档（README、advanced_config、build_and_test）并补真实字段说明。

### Phase 2：配置与模块分层（2~4天）

1. 配置模块化：
   - `config_schema.h/.cpp`（字段定义、默认值、范围校验）；
   - `config_loader.h/.cpp`（文件/字符串加载）；
2. companion协议抽离：
   - `companion_protocol.h/.cpp`（读写帧、版本号）；
3. 注入执行器抽离：
   - `inject_runtime.h/.cpp`（wait/delay/inject/cleanup）。

### Phase 3：能力闭环与可测性（3~5天）

1. 明确 `thread_disguise_name`：要么实现，要么移除字段；
2. 明确 `tracer_mode`：要么实现 block，要么文档下调为 probe-only；
3. 为 remapper/solist/config parser 增加最小回归测试（至少 host 侧单元测试）；
4. 增加“配置自检日志”（每目标最终生效配置打印摘要）。

---

## 9. 我建议的下一步动作

建议先做一个“小而稳”的 PR：

1. 修复路径一致性（README/docs/config样例/uninstall/fallback）；
2. 修复 remapper 的 3 个确定性问题（指针生命周期、MAP_FAILED、mremap检查）；
3. 明确并收敛 `thread_disguise_name` 与 `tracer_mode` 的对外语义。

这个 PR 不改核心注入行为，但能显著降低后续重构风险。

---

## 10. 附：关键入口文件索引

- 构建与打包：`module/build.gradle`、`module.gradle`、`template/magisk_module/customize.sh`
- Zygisk主入口：`module/src/jni/main_zygisk.cpp`
- Riru入口：`module/src/jni/main_riru.cpp`
- 注入流程：`module/src/jni/inject.cpp`
- 配置解析：`module/src/jni/config.cpp`
- 子进程门控：`module/src/jni/child_gating.cpp`
- 隐藏逻辑：`module/src/jni/remapper.cpp`、`module/src/jni/solist_patch.cpp`
- tracer：`module/src/jni/tracer/tracer_main.cpp`、`module/src/jni/tracer/syscall_handler.cpp`
- 动态hook：`module/src/jni/dobby_hook.cpp`
