#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
独立字节验收测试

不导入被测实现；用 struct 按 PG17 协议 3 逐字节独立构造 pgoutput 消息，
以子进程方式运行 ../repcollect.py，校验退出码、stderr 令牌与输出文件。

运行: python3 tests/acceptance.py     （退出码 0 表示全部通过）
"""

import base64
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(HERE, os.pardir, "repcollect.py")


# ---------------------------------------------------------------------------
# 独立字节构造器（与被测实现零共享）
# ---------------------------------------------------------------------------

def S(xid, first):
    return b"S" + struct.pack(">IB", xid, first)

def E():
    return b"E"

def stream_commit(xid, flags=0, c_lsn=0, e_lsn=0, ts=0):
    return b"c" + struct.pack(">IBQQQ", xid, flags, c_lsn, e_lsn, ts)

def A(xid, sub):
    return b"A" + struct.pack(">II", xid, sub)

def prepare(xid, gid, flags=0):
    return b"p" + struct.pack(">BQQQI", flags, 0, 0, 0, xid) + gid.encode("utf-8") + b"\x00"

def commit_prepared(xid, gid, flags=0):
    return b"K" + struct.pack(">BQQQI", flags, 0, 0, 0, xid) + gid.encode("utf-8") + b"\x00"

def rollback_prepared(xid, gid, flags=0):
    return b"r" + struct.pack(">BQQQI", flags, 0, 0, 0, xid) + gid.encode("utf-8") + b"\x00"

def R(xid, oid, cols, ns=b"public", name=b"t"):
    """cols: [(flags, 列名 bytes, 类型OID, 类型修饰符)]"""
    out = b"R" + struct.pack(">II", xid, oid) + ns + b"\x00" + name + b"\x00"
    out += struct.pack(">BH", 0x64, len(cols))
    for flags, cname, typ, mod in cols:
        out += struct.pack(">B", flags) + cname + b"\x00" + struct.pack(">Ii", typ, mod)
    return out

def T(*cells):
    """TupleData：单元为 "n"/"u" 或 ("t"/"b", 原值 bytes)。"""
    out = struct.pack(">H", len(cells))
    for cell in cells:
        if cell in ("n", "u"):
            out += cell.encode("ascii")
        else:
            kind, val = cell
            out += kind.encode("ascii") + struct.pack(">i", len(val)) + val
    return out

def I(xid, oid, new):
    return b"I" + struct.pack(">II", xid, oid) + b"N" + new

def U(xid, oid, new, old=None, mark="K"):
    out = b"U" + struct.pack(">II", xid, oid)
    if old is not None:
        out += mark.encode("ascii") + old
    return out + b"N" + new

def D(xid, oid, old, mark="K"):
    return b"D" + struct.pack(">II", xid, oid) + mark.encode("ascii") + old


def hx(*msgs):
    return [m.hex() for m in msgs]

def b64(val):
    return base64.b64encode(val).decode("ascii")


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------

class CaseFail(Exception):
    pass

def check(cond, msg):
    if not cond:
        raise CaseFail(msg)

def run_text(input_bytes, prefill=None):
    """以 input_bytes 为输入文件运行入口；prefill 为预先存在的输出文件内容。
    返回 (退出码, stderr 令牌, 输出 JSON 或 None, 输出原始字节或 None)。"""
    with tempfile.TemporaryDirectory() as td:
        inp = os.path.join(td, "in.json")
        outp = os.path.join(td, "out.json")
        with open(inp, "wb") as fh:
            fh.write(input_bytes)
        if prefill is not None:
            with open(outp, "wb") as fh:
                fh.write(prefill)
        proc = subprocess.run([sys.executable, "-I", ENTRY, inp, outp],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err = proc.stderr.decode("utf-8", "replace").strip()
        out_raw = None
        if os.path.exists(outp):
            with open(outp, "rb") as fh:
                out_raw = fh.read()
        out_json = None
        if out_raw is not None:
            try:
                out_json = json.loads(out_raw.decode("utf-8"))
            except ValueError:
                pass
        return proc.returncode, err, out_json, out_raw

def run_items(items, prefill=None):
    return run_text(json.dumps(items).encode("utf-8"), prefill)


# ---------------------------------------------------------------------------
# 验收用例
# ---------------------------------------------------------------------------

CASES = []

def case(fn):
    CASES.append(fn)
    return fn


@case
def t_empty_input():
    code, err, out, _ = run_items([])
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))


@case
def t_json_errors_report_dollar():
    for raw in (b"[", b"{}", b"123", b'"s"', b'["a", 1]', b'["a", null]',
                b"\xff\xfe[]", b'["a"] trailing', b""):
        code, err, out, _ = run_text(raw)
        check(code == 1 and err == "$", "%r: code=%s err=%s" % (raw, code, err))


@case
def t_bad_hex_is_message_error():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    for items, idx in ((["zz"], "0"), (["abc"], "0"), (["AB"], "0"),
                       ([""], "0"), (["5a"], "0"),
                       (hx(S(1, 1), r1) + ["zz"], "2")):
        code, err, _, _ = run_items(list(items))
        check(code == 1 and err == idx, "%s: code=%s err=%s" % (items, code, err))


@case
def t_worked_example_from_spec():
    """顶层 1 内子 2、3 各插入一次，段结束后 A(1,2) 再 c(1)，仅保留子 3 变更。"""
    r1 = R(1, 100, [(1, b"id", 23, -1), (0, b"val", 25, -1)])
    msgs = [
        S(1, 1),                                    # 0
        r1,                                         # 1
        I(2, 100, T(("t", b"a"), ("t", b"b"))),     # 2 子 2 插入
        I(3, 100, T(("t", b"c"), "n")),             # 3 子 3 插入
        E(),                                        # 4
        A(1, 2),                                    # 5 撤销子 2
        stream_commit(1),                           # 6
    ]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{
        "xid": 1,
        "changes": [[3, "I", r1.hex(), None, [["t", b64(b"c")], ["n"]]]],
    }]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_interleaved_commit_order():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    msgs = [
        S(1, 1),                            # 0
        r1,                                 # 1
        I(1, 100, T(("t", b"x"))),          # 2
        E(),                                # 3
        S(2, 1),                            # 4
        I(2, 100, T(("t", b"y"))),          # 5
        E(),                                # 6
        stream_commit(2),                   # 7 先提交 2
        stream_commit(1),                   # 8
    ]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [
        {"xid": 2, "changes": [[5, "I", r1.hex(), None, [["t", b64(b"y")]]]]},
        {"xid": 1, "changes": [[2, "I", r1.hex(), None, [["t", b64(b"x")]]]]},
    ]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_multi_segment_accumulates():
    r1 = R(9, 100, [(0, b"a", 25, -1)])
    msgs = [
        S(9, 1), r1, I(9, 100, T(("t", b"1"))), E(),
        S(9, 0), I(9, 100, T(("t", b"2"))), E(),
        stream_commit(9),
    ]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 9, "changes": [
        [2, "I", r1.hex(), None, [["t", b64(b"1")]]],
        [5, "I", r1.hex(), None, [["t", b64(b"2")]]],
    ]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_update_delete_forms():
    r1 = R(7, 50, [(0, b"a", 25, -1), (0, b"b", 25, -1)])
    msgs = [
        S(7, 1),                                                            # 0
        r1,                                                                 # 1
        U(7, 50, T(("t", b"n1"), "u"), old=T(("t", b"o1"), ("t", b"o2"))),  # 2 K 旧元组
        U(7, 50, T(("t", b"n2"), ("t", b"n3")),
          old=T(("t", b"p1"), ("t", b"p2")), mark="O"),                     # 3 O 旧元组
        U(7, 50, T(("t", b"n4"), "n")),                                     # 4 无旧元组
        D(7, 50, T(("t", b"d1"), ("t", b"d2")), mark="O"),                  # 5
        E(),                                                                # 6
        stream_commit(7),                                                   # 7
    ]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 7, "changes": [
        [2, "U", r1.hex(), [["t", b64(b"o1")], ["t", b64(b"o2")]],
         [["t", b64(b"n1")], ["u"]]],
        [3, "U", r1.hex(), [["t", b64(b"p1")], ["t", b64(b"p2")]],
         [["t", b64(b"n2")], ["t", b64(b"n3")]]],
        [4, "U", r1.hex(), None, [["t", b64(b"n4")], ["n"]]],
        [5, "D", r1.hex(), [["t", b64(b"d1")], ["t", b64(b"d2")]], None],
    ]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_unterminated_not_output():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    ins = I(1, 100, T(("t", b"x")))
    # 活跃顶层未提交
    code, err, out, _ = run_items(hx(S(1, 1), r1, ins, E()))
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))
    # 已预备未 K/r
    code, err, out, _ = run_items(hx(S(1, 1), r1, ins, E(), prepare(1, "g")))
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))
    # 已整体撤销
    code, err, out, _ = run_items(hx(S(1, 1), r1, ins, E(), A(1, 1)))
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))
    # 已预备回滚
    code, err, out, _ = run_items(
        hx(S(1, 1), r1, ins, E(), prepare(1, "g"), rollback_prepared(1, "g")))
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))


@case
def t_unclosed_segment_reports_S_index():
    code, err, _, _ = run_items(hx(S(1, 1), R(1, 100, [])))
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    code, err, _, _ = run_items(hx(S(1, 1), E(), S(2, 1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))


@case
def t_relation_rules():
    # 未定义 OID 拒绝
    code, err, _, _ = run_items(hx(S(1, 1), I(1, 999, T(("t", b"x"))), E(),
                                   stream_commit(1)))
    check(code == 1 and err == "1", "code=%s err=%s" % (code, err))
    r2 = R(1, 100, [(0, b"a", 25, -1), (0, b"b", 25, -1)])
    # 新元组列数不匹配
    code, err, _, _ = run_items(hx(S(1, 1), r2, I(1, 100, T(("t", b"x"))), E(),
                                   stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # 旧元组列数同样须匹配
    code, err, _, _ = run_items(hx(
        S(1, 1), r2, U(1, 100, T(("t", b"x"), ("t", b"y")), old=T(("t", b"o"))),
        E(), stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))


@case
def t_relation_redefine_latest_wins():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    r2 = R(1, 100, [(0, b"a", 25, -1), (0, b"b", 25, -1)])
    msgs = [S(1, 1), r1, I(1, 100, T(("t", b"1"))), r2,
            I(1, 100, T(("t", b"2"), ("t", b"3"))), E(), stream_commit(1)]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 1, "changes": [
        [2, "I", r1.hex(), None, [["t", b64(b"1")]]],
        [4, "I", r2.hex(), None, [["t", b64(b"2")], ["t", b64(b"3")]]],
    ]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))
    # 重定义后旧列数被拒
    code, err, _, _ = run_items(hx(S(1, 1), r1, r2, I(1, 100, T(("t", b"1"))),
                                   E(), stream_commit(1)))
    check(code == 1 and err == "3", "code=%s err=%s" % (code, err))


@case
def t_rollback_keeps_relation_cache():
    r1 = R(2, 100, [(0, b"a", 25, -1)])   # 由随后被撤销的子事务 2 定义
    msgs = [S(1, 1), r1, E(), A(1, 2),
            S(1, 0), I(1, 100, T(("t", b"v"))), E(), stream_commit(1)]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 1, "changes": [[5, "I", r1.hex(), None, [["t", b64(b"v")]]]]}]
    check(code == 0 and out ==	expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_prepare_flows():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    ins = I(1, 100, T(("t", b"x")))
    # p + K：提交输出
    code, err, out, _ = run_items(
        hx(S(1, 1), r1, ins, E(), prepare(1, "g1"), commit_prepared(1, "g1")))
    expect = [{"xid": 1, "changes": [[2, "I", r1.hex(), None, [["t", b64(b"x")]]]]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))
    # GID 不匹配
    code, err, _, _ = run_items(
        hx(S(1, 1), r1, ins, E(), prepare(1, "g1"), commit_prepared(1, "g2")))
    check(code == 1 and err == "5", "code=%s err=%s" % (code, err))
    # K 未知 xid
    code, err, _, _ = run_items(hx(commit_prepared(7, "g")))
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 未预备却 r
    code, err, _, _ = run_items(hx(S(1, 1), r1, E(), rollback_prepared(1, "g")))
    check(code == 1 and err == "3", "code=%s err=%s" % (code, err))
    # 预备后 c / S / p / A 均被拒
    for tail in (stream_commit(1), S(1, 0), prepare(1, "g"), A(1, 1)):
        code, err, _, _ = run_items(hx(S(1, 1), r1, E(), prepare(1, "g"), tail))
        check(code == 1 and err == "4", "tail=%r code=%s err=%s" % (tail, code, err))
    # 预备事务与他事务交错，按 K/c 先后定提交序
    msgs = [S(1, 1), r1, ins, E(), prepare(1, "g"),
            S(2, 1), I(2, 100, T(("t", b"y"))), E(),
            stream_commit(2), commit_prepared(1, "g")]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [
        {"xid": 2, "changes": [[6, "I", r1.hex(), None, [["t", b64(b"y")]]]]},
        {"xid": 1, "changes": [[2, "I", r1.hex(), None, [["t", b64(b"x")]]]]},
    ]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_abort_whole_and_xid_reuse():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    code, err, out, _ = run_items(hx(S(1, 1), r1, I(1, 100, T(("t", b"x"))),
                                     E(), A(1, 1)))
    check(code == 0 and out == [], "code=%s err=%s out=%s" % (code, err, out))
    # 终结后复用顶层 xid：S / c / p / A 一律拒绝
    for tail in (S(1, 1), stream_commit(1), prepare(1, "g"), A(1, 1)):
        code, err, _, _ = run_items(hx(S(1, 1), E(), stream_commit(1), tail))
        check(code == 1 and err == "3", "tail=%r code=%s err=%s" % (tail, code, err))
    code, err, _, _ = run_items(hx(S(1, 1), E(), A(1, 1), S(1, 1)))
    check(code == 1 and err == "3", "code=%s err=%s" % (code, err))


@case
def t_xid_role_conflicts():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    # 子事务 xid 被另一顶层段内引用
    code, err, _, _ = run_items(hx(S(1, 1), r1, I(5, 100, T(("t", b"x"))), E(),
                                   S(2, 1), I(5, 100, T(("t", b"y"))), E()))
    check(code == 1 and err == "5", "code=%s err=%s" % (code, err))
    # 活跃顶层 xid 被当作子事务引用
    code, err, _, _ = run_items(hx(S(1, 1), r1, E(), S(2, 1),
                                   I(1, 100, T(("t", b"y"))), E()))
    check(code == 1 and err == "4", "code=%s err=%s" % (code, err))
    # 子事务 xid 被提升为顶层
    code, err, _, _ = run_items(hx(S(1, 1), r1, I(5, 100, T(("t", b"x"))), E(),
                                   S(5, 1)))
    check(code == 1 and err == "4", "code=%s err=%s" % (code, err))
    # 终结后子事务 xid 复用
    code, err, _, _ = run_items(hx(S(1, 1), r1, I(5, 100, T(("t", b"x"))), E(),
                                   stream_commit(1), S(2, 1),
                                   I(5, 100, T(("t", b"y")))))
    check(code == 1 and err == "6", "code=%s err=%s" % (code, err))


@case
def t_unknown_sub_abort_binding():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    # 未知子 XID 绑定后撤销：正常提交，变更列表为空
    code, err, out, _ = run_items(hx(S(1, 1), r1, E(), A(1, 9), stream_commit(1)))
    check(code == 0 and out == [{"xid": 1, "changes": []}],
          "code=%s err=%s out=%s" % (code, err, out))
    # 撤销后禁再引用
    code, err, _, _ = run_items(hx(S(1, 1), r1, E(), A(1, 9), S(1, 0),
                                   I(9, 100, T(("t", b"x")))))
    check(code == 1 and err == "5", "code=%s err=%s" % (code, err))
    # 重复撤销同一子事务被拒
    code, err, _, _ = run_items(hx(S(1, 1), r1, E(), A(1, 9), A(1, 9)))
    check(code == 1 and err == "4", "code=%s err=%s" % (code, err))
    # 子事务他属，不可越顶撤销
    code, err, _, _ = run_items(hx(S(1, 1), r1, I(9, 100, T(("t", b"x"))), E(),
                                   S(2, 1), E(), A(2, 9)))
    check(code == 1 and err == "6", "code=%s err=%s" % (code, err))


@case
def t_sub_abort_filters_receive_order():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    msgs = [
        S(1, 1), r1,                            # 0,1
        I(1, 100, T(("t", b"top"))),            # 2 顶层
        I(2, 100, T(("t", b"s2"))),             # 3 子 2
        I(3, 100, T(("t", b"s3"))),             # 4 子 3
        I(2, 100, T(("t", b"s2b"))),            # 5 子 2 再次
        E(),                                    # 6
        A(1, 2),                                # 7
        stream_commit(1),                       # 8
    ]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 1, "changes": [
        [2, "I", r1.hex(), None, [["t", b64(b"top")]]],
        [4, "I", r1.hex(), None, [["t", b64(b"s3")]]],
    ]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_non_utf8_protocol_string():
    bad_ns = R(1, 100, [(0, b"a", 25, -1)], ns=b"\xff")
    code, err, _, _ = run_items(hx(S(1, 1), bad_ns, E(), stream_commit(1)))
    check(code == 1 and err == "1", "code=%s err=%s" % (code, err))
    bad_col = R(1, 100, [(0, b"\xc3\x28", 25, -1)])
    code, err, _, _ = run_items(hx(S(1, 1), bad_col, E(), stream_commit(1)))
    check(code == 1 and err == "1", "code=%s err=%s" % (code, err))
    bad_gid = b"p" + struct.pack(">BQQQI", 0, 0, 0, 0, 1) + b"\xff\x00"
    code, err, _, _ = run_items(hx(S(1, 1), E(), bad_gid))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))


@case
def t_tuple_cell_kinds():
    r1 = R(1, 100, [(0, b"a", 25, -1), (0, b"b", 25, -1),
                    (0, b"c", 25, -1), (0, b"d", 25, -1)])
    raw = bytes(range(256))
    msgs = [S(1, 1), r1, I(1, 100, T(("b", raw), "u", "n", ("t", b""))),
            E(), stream_commit(1)]
    code, err, out, _ = run_items(hx(*msgs))
    expect = [{"xid": 1, "changes": [[2, "I", r1.hex(), None,
                                      [["b", b64(raw)], ["u"], ["n"], ["t", ""]]]]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_zero_column_relation():
    r1 = R(1, 100, [])
    code, err, out, _ = run_items(hx(S(1, 1), r1, I(1, 100, T()), E(),
                                     stream_commit(1)))
    expect = [{"xid": 1, "changes": [[2, "I", r1.hex(), None, []]]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))


@case
def t_structural_errors():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    # 尾随字节
    code, err, _, _ = run_items(hx(S(1, 1), E(), stream_commit(1) + b"\x00"))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # 未知标签（'B'）
    code, err, _, _ = run_items(["42"])
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 截断
    code, err, _, _ = run_items([S(1, 1).hex()[:4]])
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 元组单元种类非法
    bad_kind = b"I" + struct.pack(">II", 1, 100) + b"N" + struct.pack(">H", 1) + b"x"
    code, err, _, _ = run_items(hx(S(1, 1), r1, bad_kind, E(), stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # 值长为负
    bad_neg = (b"I" + struct.pack(">II", 1, 100) + b"N" + struct.pack(">H", 1)
               + b"t" + struct.pack(">i", -1))
    code, err, _, _ = run_items(hx(S(1, 1), r1, bad_neg, E(), stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # 值长越界
    bad_over = (b"I" + struct.pack(">II", 1, 100) + b"N" + struct.pack(">H", 1)
                + b"t" + struct.pack(">i", 5) + b"ab")
    code, err, _, _ = run_items(hx(S(1, 1), r1, bad_over, E(), stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # D 缺少 K/O 标记
    bad_d = b"D" + struct.pack(">II", 1, 100) + b"N" + struct.pack(">H", 0)
    code, err, _, _ = run_items(hx(S(1, 1), r1, bad_d, E(), stream_commit(1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # S 首段标志非法取值
    code, err, _, _ = run_items([(b"S" + struct.pack(">IB", 1, 2)).hex()])
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 协议串无 NUL 终止
    no_nul = b"R" + struct.pack(">II", 1, 100) + b"public"
    code, err, _, _ = run_items(hx(S(1, 1), no_nul))
    check(code == 1 and err == "1", "code=%s err=%s" % (code, err))


@case
def t_misplaced_messages():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    ins = I(1, 100, T(("t", b"x")))
    # E 无段
    code, err, _, _ = run_items(hx(E()))
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 段嵌套
    code, err, _, _ = run_items(hx(S(1, 1), S(2, 1)))
    check(code == 1 and err == "1", "code=%s err=%s" % (code, err))
    # 段内 c/A/p/K/r
    for bad in (stream_commit(1), A(1, 1), prepare(1, "g"),
                commit_prepared(1, "g"), rollback_prepared(1, "g")):
        code, err, _, _ = run_items(hx(S(1, 1), bad))
        check(code == 1 and err == "1", "bad=%r code=%s err=%s" % (bad, code, err))
    # 段外 R/I/U/D
    for bad in (r1, ins, U(1, 100, T(("t", b"x"))), D(1, 100, T(("t", b"x")))):
        code, err, _, _ = run_items(hx(bad))
        check(code == 1 and err == "0", "bad=%r code=%s err=%s" % (bad, code, err))


@case
def t_first_flag_rules():
    # 新顶层首段标志须为 1
    code, err, _, _ = run_items(hx(S(1, 0)))
    check(code == 1 and err == "0", "code=%s err=%s" % (code, err))
    # 后续段标志须为 0
    code, err, _, _ = run_items(hx(S(1, 1), E(), S(1, 1)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))
    # 另一顶层的首段同样须为 1
    code, err, _, _ = run_items(hx(S(1, 1), E(), S(2, 0)))
    check(code == 1 and err == "2", "code=%s err=%s" % (code, err))


@case
def t_utf8_gid():
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    ins = I(1, 100, T(("t", b"x")))
    code, err, out, _ = run_items(
        hx(S(1, 1), r1, ins, E(), prepare(1, "事务-α"), commit_prepared(1, "事务-α")))
    expect = [{"xid": 1, "changes": [[2, "I", r1.hex(), None, [["t", b64(b"x")]]]]}]
    check(code == 0 and out == expect, "code=%s err=%s out=%s" % (code, err, out))
    code, err, _, _ = run_items(
        hx(S(1, 1), r1, E(), prepare(1, "事务"), commit_prepared(1, "事务-α")))
    check(code == 1 and err == "4", "code=%s err=%s" % (code, err))


@case
def t_output_replaced_only_on_success():
    sentinel = b'{"old": true}\n'
    # JSON 错：保留旧输出
    code, err, _, raw = run_text(b"[", prefill=sentinel)
    check(code == 1 and err == "$" and raw == sentinel,
          "code=%s err=%s raw=%s" % (code, err, raw))
    # 消息错：保留旧输出
    code, err, _, raw = run_items(hx(S(1, 1), S(2, 1)), prefill=sentinel)
    check(code == 1 and err == "1" and raw == sentinel,
          "code=%s err=%s raw=%s" % (code, err, raw))
    # 成功：替换旧输出
    r1 = R(1, 100, [(0, b"a", 25, -1)])
    code, err, out, raw = run_items(
        hx(S(1, 1), r1, I(1, 100, T(("t", b"x"))), E(), stream_commit(1)),
        prefill=sentinel)
    expect = [{"xid": 1, "changes": [[2, "I", r1.hex(), None, [["t", b64(b"x")]]]]}]
    check(code == 0 and raw != sentinel and out == expect,
          "code=%s err=%s out=%s raw=%s" % (code, err, out, raw))


# ---------------------------------------------------------------------------
# 驱动
# ---------------------------------------------------------------------------

def main():
    failures = 0
    for fn in CASES:
        try:
            fn()
            print("ok   %s" % fn.__name__)
        except CaseFail as exc:
            failures += 1
            print("FAIL %s: %s" % (fn.__name__, exc))
        except Exception as exc:  # 意外异常同样记失败
            failures += 1
            print("FAIL %s: unexpected %r" % (fn.__name__, exc))
    print("----")
    print("%d passed, %d failed" % (len(CASES) - failures, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
