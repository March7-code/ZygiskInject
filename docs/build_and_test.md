# 构建与测试指南

## 环境要求

| 工具 | 版本要求 |
|---|---|
| JDK | 11 或 17 |
| Android SDK | Build Tools 33+ |
| Android NDK | **25.2.9519653**（固定版本，build.gradle 指定） |
| Gradle | 项目自带 wrapper，无需单独安装 |
| ADB | 已配置到 PATH |
| 设备 | Android 8.0+，已 root，已安装 Magisk（Zygisk 模式） |

NDK 版本必须精确匹配，可通过 Android Studio SDK Manager 或命令安装：
```
sdkmanager "ndk;25.2.9519653"
```

---

## 构建

项目使用 Gradle + ndk-build 构建，产物是一个 Magisk 模块 zip。

### 构建 Zygisk 版本（推荐）

```bash
cd E:\MyTool\ZygiskFrida-main
./gradlew zipZygiskRelease
```

产物路径：
```
out/ZygiskFrida-<version>-zygisk-release.zip
```

### 构建 Debug 版本（含日志）

```bash
./gradlew zipZygiskDebug
```

### 其他常用 Gradle 任务

| 任务 | 说明 |
|---|---|
| `zipZygiskRelease` | 构建 Zygisk release zip |
| `zipZygiskDebug` | 构建 Zygisk debug zip |
| `zipRiruRelease` | 构建 Riru release zip |
| `pushZygiskRelease` | 构建后 adb push 到 /data/local/tmp/ |
| `flashZygiskRelease` | push 后通过 magisk --install-module 安装 |
| `flashAndRebootZygiskRelease` | 安装后自动重启 |

> `downloadFrida` 任务会自动从 GitHub 下载 gadget，需要网络。
> 如果网络受限，手动下载后放到 `gadget/` 目录，文件名格式为
> `libgadget-arm64.so.xz`、`libgadget-arm.so.xz` 等。

---

## 安装到设备

### 方式一：一键安装并重启

```bash
./gradlew flashAndRebootZygiskRelease
```

### 方式二：手动安装

```bash
# 推送 zip
adb push out/ZygiskFrida-*-zygisk-release.zip /data/local/tmp/

# 安装模块
adb shell su -c "magisk --install-module /data/local/tmp/ZygiskFrida-*-zygisk-release.zip"

# 重启
adb reboot
```

重启后模块生效。

---

## 配置

模块安装后，配置目录在 `/data/adb/re.zyg.fri/`（已从原来的 `/data/local/tmp` 迁移）。

### 创建配置文件

```bash
adb shell su -c "cp /data/adb/re.zyg.fri/config.json.example /data/adb/re.zyg.fri/config.json"
adb shell su -c "nano /data/adb/re.zyg.fri/config.json"
```

### 最小配置示例

```json
{
  "targets": [
    {
      "app_name": "com.example.target",
      "enabled": true,
      "start_up_delay_ms": 0,
      "injected_libraries": [
        {
          "path": "/data/adb/re.zyg.fri/libgadget.so"
        }
      ]
    }
  ]
}
```

### 带线程名伪装的配置

```json
{
  "targets": [
    {
      "app_name": "com.example.target",
      "enabled": true,
      "start_up_delay_ms": 0,
      "thread_disguise_name": "RenderThread",
      "injected_libraries": [
        {
          "path": "/data/adb/re.zyg.fri/libgadget.so"
        }
      ]
    }
  ]
}
```

`thread_disguise_name` 规则：
- 可选字段，不填默认 `pool-1-thread-1`
- 长度不超过 15 字符（内核限制）
- 建议使用目标 app 中真实存在的线程名，如 `RenderThread`、`GLThread`、`OkHttp`

---

## 测试

### 1. 确认模块加载

重启后检查模块是否正常加载：

```bash
adb shell su -c "magisk --list-modules" | grep zygiskfrida
```

### 2. 查看注入日志

```bash
adb logcat -s ZygiskFrida
```

正常注入时应看到：
```
ZygiskFrida: App detected: com.example.target
ZygiskFrida: Injecting /data/adb/re.zyg.fri/libgadget.so
ZygiskFrida: Injected ... with handle 0x...
ZygiskFrida: [thread_rename] pthread_setname_np hook installed
ZygiskFrida: [thread_rename] intercepted 'frida-gadget' -> 'RenderThread'
ZygiskFrida: [thread_rename] all frida threads renamed, hook removed
ZygiskFrida: [solist_patch] soinfo offsets: base=0x... next=0x...
ZygiskFrida: [solist_patch] removed soinfo for 0x... from solist
```

### 3. 验证 frida 连接

gadget 默认 listen 模式，端口 27042：

```bash
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget
```

connect 模式需要先在同一网络启动 frida-server：

```bash
# PC 端
frida-server -l 0.0.0.0:27042

# 设备端 gadget config 配置 address 指向 PC IP
```

### 4. 验证隐藏效果

在 frida session 中执行：

```javascript
// 验证 solist 隐藏：gadget 不应出现在枚举结果中
Process.enumerateModules().forEach(m => {
    if (m.path.includes('gadget') || m.path.includes('frida')) {
        console.log('DETECTED:', m.path);
    }
});

// 验证线程名伪装
Process.enumerateThreads().forEach(t => {
    console.log(t.id, t.name);
});
```

### 5. 验证 maps 隐藏

```bash
adb shell su -c "cat /proc/$(pidof com.example.target)/maps | grep -i frida"
# 应无输出
```

---

## 常见问题

**注入失败，日志显示 `Failed to inject`**
- 检查 so 文件路径是否正确
- 检查文件权限：`adb shell su -c "ls -la /data/adb/re.zyg.fri/"`
- 权限应为 `0644`，owner `root`

**solist_patch 失败**
- 日志中查找 `[solist_patch] failed`
- 可能是 Android 版本的 soinfo 结构布局不兼容
- 不影响注入本身，gadget 仍然正常工作，只是 solist 未隐藏

**线程名 hook 未生效**
- 检查日志是否有 `pthread_setname_np hook installed`
- 如果显示 `DobbyHook failed`，可能是 SELinux 或内存保护问题

**配置修改后不生效**
- 配置在 app 启动时读取，需要强杀目标 app 再重新启动
- 不需要重启设备
