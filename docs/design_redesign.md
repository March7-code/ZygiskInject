# ZygiskFrida 改造设计方案

## 背景与目标

现有 ZygiskFrida 存在以下问题：

1. 配置和 gadget 文件存放在 `/data/local/tmp/re.zyg.fri/`，该目录全局可读，容易被检测工具扫描发现
2. 注入后只做了 `/proc/maps` 隐藏（remapper），未隐藏 linker solist，`dl_iterate_phdr` / `dladdr` 仍可枚举到 gadget
3. 模块主动读取磁盘配置文件，磁盘上存在持久化痕迹

改造目标：

- 配置和 gadget 文件迁移到目标 app 私有目录，外部进程无法访问
- 配置通过 IPC 动态下发，不落磁盘
- 补充 solist 隐藏，对抗 `dl_iterate_phdr` 类检测
- 配套一个管理 App 负责文件部署和配置下发

**职责划分原则：模块只负责注入，App 负责管理 gadget 的一切配置。**

---

## 整体架构

```
┌─────────────────────────────────────────────────────┐
│                   配套管理 App                        │
│                                                     │
│  ① 用户选择目标包名 + 通讯模式                          │
│  ② su 将 gadget.so 部署到目标 app 私有目录              │
│  ③ 通过 Unix Socket 向 Companion 下发注入配置           │
└──────────────────┬──────────────────────────────────┘
                   │ Unix Domain Socket
                   │ /dev/socket/re.zyg.fri
                   ▼
┌─────────────────────────────────────────────────────┐
│              Zygisk Companion Process               │
│                    (root 权限常驻)                    │
│                                                     │
│  - 监听 /dev/socket/re.zyg.fri                       │
│  - 接收配置并缓存到内存 (pkg → so_path)                 │
│  - 响应模块的 connectCompanion() 查询                  │
└──────────────────┬──────────────────────────────────┘
                   │ connectCompanion() (Zygisk 内部)
                   ▼
┌─────────────────────────────────────────────────────┐
│              Zygisk 模块 (目标进程内)                  │
│                                                     │
│  preAppSpecialize:                                  │
│    - connectCompanion() 查询当前包名是否有配置           │
│    - 有则拿到 so_path，存入成员变量                      │
│                                                     │
│  postAppSpecialize:                                 │
│    - 用 so_path 执行 inject_lib()                    │
│    - remap_lib() 隐藏 /proc/maps                     │
│    - solist_remove() 隐藏 linker solist  ← 新增       │
└─────────────────────────────────────────────────────┘
```

---

## 各组件详细设计

### 1. 配套管理 App

#### 职责

- 提供 UI 让用户选择目标包名
- 用户自行提供 gadget.so，App 负责将其部署到目标 app 私有目录
- 生成 gadget config 文件（固定使用 connect 模式，配置目标 frida-server 地址）
- 通过 Unix Socket 向 Companion 下发注入配置
- 管理已部署的目标列表（增删改查）
- 验证 solist_patch 在当前设备是否可用，并将结果告知 Companion

#### 为什么只用 connect 模式

listen 模式下 gadget 会在本地开启监听端口，任何端口扫描工具都能发现。connect 模式由 gadget 主动向外连接，本地不开放端口，检测面更小。

#### gadget 部署流程

```
源文件: 用户提供的 gadget.so（由 App 的文件选择器导入）
目标路径: /data/data/<pkg>/files/.cache/<disguised_name>.so

执行步骤 (su):
  1. mkdir -p /data/data/<pkg>/files/.cache
  2. cp <gadget_src> /data/data/<pkg>/files/.cache/<name>.so
  3. 生成 config 并写入 /data/data/<pkg>/files/.cache/<name>.config.so
  4. chown <app_uid>:<app_gid> 上述两个文件
  5. chmod 700 上述两个文件
```

#### gadget config 文件内容（由 App 生成，固定 connect 模式）

```json
{
  "interaction": {
    "type": "connect",
    "address": "192.168.x.x",
    "port": 27042
  }
}
```

address 和 port 由用户在 App 内配置。

#### 文件名伪装

gadget 文件名不使用 `libgadget.so`，改用不显眼的通用名称，例如：
- `libcore.so` + `libcore.config.so`
- `libruntime.so` + `libruntime.config.so`

具体名称在 App 内可配置，下发给 Companion 时一并传递 so_path 绝对路径。

#### solist_patch 可用性验证

solist_patch 依赖对 linker 内部结构的扫描，不同 Android 版本的 soinfo 布局可能有差异。管理 App 在部署时执行一次验证（在 App 自身进程内尝试扫描 soinfo 结构），将验证结果（`solist_patch_enabled: true/false`）一并下发给 Companion，模块根据此标志决定是否执行 solist_remove。

#### 向 Companion 下发配置的协议

连接 `/dev/socket/re.zyg.fri`，发送 JSON：

```json
{
  "action": "add",
  "pkg": "com.example.target",
  "so_path": "/data/data/com.example.target/files/.cache/libcore.so",
  "start_up_delay_ms": 0,
  "solist_patch_enabled": true
}
```

支持的 action：
- `add`：添加或更新一条注入配置
- `remove`：移除一条注入配置
- `list`：查询当前所有配置（用于 App 展示状态）

---

### 2. Zygisk Companion Process

#### 职责

- 在 Zygisk 加载时启动，以 root 权限常驻
- 创建并监听 `/dev/socket/re.zyg.fri`，接受来自管理 App 的配置
- 维护内存中的配置表 `map<pkg_name, inject_config>`
- 响应模块通过 `connectCompanion()` 发来的查询请求

#### 内存配置结构

```cpp
struct inject_config {
    std::string so_path;
    uint64_t start_up_delay_ms;
    bool solist_patch_enabled;  // 由管理 App 验证后下发
};

// 全局配置表，仅存在于内存
static std::map<std::string, inject_config> g_config_map;
```

#### 与模块的通信协议（connectCompanion socket）

模块发送包名，Companion 回复是否有配置及配置内容：

```
模块 → Companion:  [uint32_t pkg_len][pkg_name bytes]
Companion → 模块:  [uint8_t found]
                   如果 found == 1:
                   [uint32_t path_len][so_path bytes]
                   [uint64_t start_up_delay_ms]
                   [uint8_t solist_patch_enabled]
```

使用定长头部 + 变长数据的简单二进制协议，避免引入 JSON 解析依赖。

#### 与管理 App 的通信协议（Unix Socket）

接收 JSON 文本，回复简单状态：

```
App → Companion:  [uint32_t json_len][json bytes]
Companion → App:  [uint8_t result]  // 0=ok, 1=error
```

#### 安全考虑

`/dev/socket/re.zyg.fri` 权限设为 `0600`，owner 为 root，防止普通应用连接。管理 App 通过 su 执行连接，或者 App 本身申请 root 权限后直接连接。

---

### 3. Zygisk 模块改造

#### preAppSpecialize 新增逻辑

```
1. 获取当前包名 (args->nice_name)
2. connectCompanion() 获取 socket fd
3. 发送包名查询
4. 收到响应：
   - found=0 → setOption(DLCLOSE_MODULE_LIBRARY)，退出
   - found=1 → 保存 so_path 和 delay 到成员变量
```

注意：`connectCompanion()` 只能在 `pre[XXX]Specialize` 阶段调用，SELinux 限制。

#### postAppSpecialize 改造

```
1. 检查成员变量中是否有 so_path（preAppSpecialize 阶段拿到的）
2. 没有 → 直接返回
3. 有 →
   a. wait_for_init()
   b. delay_start_up()
   c. inject_lib(so_path)
   d. remap_lib(so_path)                          ← 现有逻辑
   e. if solist_patch_enabled: solist_remove()    ← 新增，由 App 验证后决定是否启用
```

#### 移除文件读取逻辑

- `config.cpp` / `config.h` 整体移除
- `inject.cpp` 中的 `check_and_inject()` 重构，不再读取 `/data/local/tmp` 或任何磁盘配置
- `module_dir` 硬编码路径全部删除

---

### 4. solist 隐藏（新增模块）

#### 原理

Android linker 内部维护一个 `soinfo` 链表（`solist`），`dl_iterate_phdr` 和 `dladdr` 都依赖这个链表。将 gadget 的 `soinfo` 节点从链表中摘除后，这两个 API 就无法发现 gadget。

#### 实现步骤

参考 AndKittyInjector 的 `SoInfoPatch` 实现，在 in-process 环境下简化：

```
1. 用 xdl_dsym 从 linker 中找到 __dl__ZL6solist 和 __dl__ZL6sonext 的地址
2. 读取 solist 链表头指针（直接解引用，无需远程读写）
3. 动态扫描 soinfo 结构体，找到 base_offset 和 next_offset
   （不硬编码偏移，兼容 Android 5~15）
4. 遍历链表，找到 base == gadget_load_address 的节点
5. prev->next = target->next（摘除节点）
6. 如果摘除的是尾节点，同步更新 sonext
```

#### 与 AndKittyInjector 的差异

| 项目 | AndKittyInjector | 本方案 |
|---|---|---|
| 运行上下文 | ptrace 远程进程 | in-process，直接指针操作 |
| 内存读写 | 远程 readMem / memPatch | 直接解引用 |
| NativeBridge | 支持 x86 模拟 ARM | 暂不需要 |
| 代码复杂度 | 高 | 低 |

#### 新增文件

- `solist_patch.cpp`
- `solist_patch.h`

---

## 文件改动汇总

### ZygiskFrida 模块

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `main_zygisk.cpp` | 修改 | 增加 `preAppSpecialize`，增加 Companion handler，增加成员变量 |
| `inject.cpp` | 修改 | 移除文件读取，接收外部传入配置，增加 solist_remove 调用 |
| `inject.h` | 修改 | 更新函数签名 |
| `config.cpp` | 删除 | 不再需要 |
| `config.h` | 删除 | 不再需要 |
| `solist_patch.cpp` | 新增 | solist 隐藏实现 |
| `solist_patch.h` | 新增 | solist 隐藏接口 |
| `Android.mk` | 修改 | 更新编译文件列表 |

### Magisk 模块安装脚本

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `customize.sh` | 修改 | 移除 `/data/local/tmp` 目录创建和 gadget 解压逻辑 |

### 新增：配套管理 App

独立 Android 项目，主要模块：

| 模块 | 说明 |
|---|---|
| `GadgetManager` | 用户提供的 gadget.so 导入、部署到目标 app 私有目录（su） |
| `CompanionClient` | Unix Socket 客户端，向 Companion 下发配置 |
| `TargetListUI` | 目标包列表管理界面 |
| `GadgetConfigUI` | connect 模式配置界面（frida-server 地址和端口） |
| `SolistPatchVerifier` | 在 App 自身进程内验证 solist_patch 是否可用，结果随配置下发 |

---

## 数据流总览

```
用户操作管理 App
    │
    ├─ [一次性] su 部署 gadget.so 到 /data/data/<pkg>/files/.cache/
    │
    └─ [配置下发] Unix Socket → Companion 内存缓存
                                    │
                          每次 app 启动时
                                    │
                          preAppSpecialize
                          connectCompanion() 查询
                                    │
                          postAppSpecialize
                          inject → remap → solist_remove
```

---

## 遗留问题 / 待确认

1. **Companion socket 重启恢复**：设备重启后 Companion 内存清空，需要管理 App 重新下发配置。是否需要 App 开机自启动自动重新下发？
2. **多架构 gadget**：目标 app 可能是 32 位或 64 位，管理 App 在部署时需要根据目标 app 的 ABI 让用户选择对应架构的 gadget 文件。
3. **solist_patch 验证时机**：App 在部署 gadget 时执行一次验证即可，还是每次下发配置前都重新验证？建议部署时验证一次，结果持久化在 App 本地。
