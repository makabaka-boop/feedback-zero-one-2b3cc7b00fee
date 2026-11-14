#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
repcollect — 复制采集后端

输入为 UTF-8 JSON 数组，每项是一条完整 pgoutput 消息的小写偶数位 hex
（PostgreSQL 17 逻辑复制协议，协议版本 3，无外层封装，仅流式事务）。
按提交序输出 {xid, changes} 数组。

用法:
    repcollect.py INPUT OUTPUT

退出码:
    0  成功；OUTPUT 被原子替换为新结果
    1  输入被整次拒绝；stderr 打印出错消息的零基消息号，JSON 级错误打印 $
    2  用法或 I/O 错误（OUTPUT 不被触碰）

解析裁决均为手写，仅用 struct/base64 等字节库。
"""

import base64
import json
import os
import re
import struct
import sys

_HEX_RE = re.compile(r"[0-9a-f]*")


class Reject(Exception):
    """整次输入被拒绝。index 为出错消息的零基消息号。"""

    def __init__(self, index):
        super().__init__(index)
        self.index = index


# ---------------------------------------------------------------------------
# 字节游标：单条消息体上的结构解析
# ---------------------------------------------------------------------------

class Reader:
    __slots__ = ("buf", "pos", "index")

    def __init__(self, buf, index):
        self.buf = buf
        self.pos = 0
        self.index = index

    def fail(self):
        raise Reject(self.index)

    def take(self, n):
        if n < 0 or self.pos + n > len(self.buf):
            self.fail()
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def cstring(self):
        """协议 String 字段：NUL 终止，必须为合法 UTF-8。"""
        end = self.buf.find(b"\x00", self.pos)
        if end < 0:
            self.fail()
        raw = self.buf[self.pos:end]
        self.pos = end + 1
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self.fail()

    def finish(self):
        """消息必须被恰好消费完，不允许尾随字节。"""
        if self.pos != len(self.buf):
            self.fail()


# ---------------------------------------------------------------------------
# 消息结构解析（无状态）：PG17 协议 3
# ---------------------------------------------------------------------------

def parse_tuple(r):
    """TupleData -> 列 JSON 数组：n/u 为 [tag]，t/b 为 [tag, 带填充 Base64 原值]。"""
    cols = []
    for _ in range(r.u16()):
        kind = chr(r.u8())
        if kind in ("n", "u"):
            cols.append([kind])
        elif kind in ("t", "b"):
            length = r.i32()
            if length < 0:
                r.fail()
            cols.append([kind, base64.b64encode(r.take(length)).decode("ascii")])
        else:
            r.fail()
    return cols


def parse_relation(r):
    """R 消息 -> (xid, oid, 列数)。列定义逐项校验结构，内容不保留。"""
    xid = r.u32()
    oid = r.u32()
    r.cstring()          # 命名空间
    r.cstring()          # 关系名
    r.u8()               # replica identity
    ncols = r.u16()
    for _ in range(ncols):
        r.u8()           # 列标志
        r.cstring()      # 列名
        r.u32()          # 列类型 OID
        r.i32()          # 类型修饰符
    return (xid, oid, ncols)


def parse_dml(r, tag):
    """I/U/D 消息 -> (xid, oid, old, new)；old/new 为列数组或 None。"""
    xid = r.u32()
    oid = r.u32()
    old = None
    if tag == "I":
        if chr(r.u8()) != "N":
            r.fail()
        new = parse_tuple(r)
    elif tag == "U":
        mark = chr(r.u8())
        if mark in ("K", "O"):
            old = parse_tuple(r)
            mark = chr(r.u8())
        if mark != "N":
            r.fail()
        new = parse_tuple(r)
    else:  # "D"
        if chr(r.u8()) not in ("K", "O"):
            r.fail()
        old = parse_tuple(r)
        new = None
    return (xid, oid, old, new)


def parse_message(raw, index):
    """结构解析一条完整消息，返回 (tag, fields)。LSN/时间/未用标志解析后忽略。"""
    r = Reader(raw, index)
    tag = chr(r.u8())
    if tag == "S":                       # Stream Start
        xid = r.u32()
        first = r.u8()
        if first not in (0, 1):
            r.fail()
        fields = (xid, first)
    elif tag == "E":                     # Stream Stop
        fields = ()
    elif tag == "c":                     # Stream Commit
        fields = (r.u32(), r.u8(), r.u64(), r.u64(), r.u64())
    elif tag == "A":                     # Stream Abort
        fields = (r.u32(), r.u32())
    elif tag in ("p", "K", "r"):         # Begin Prepare / Commit Prepared / Rollback Prepared
        fields = (r.u8(), r.u64(), r.u64(), r.u64(), r.u32(), r.cstring())
    elif tag == "R":                     # Relation
        fields = parse_relation(r)
    elif tag in ("I", "U", "D"):         # Insert / Update / Delete
        fields = parse_dml(r, tag)
    else:
        r.fail()
    r.finish()
    return tag, fields


# ---------------------------------------------------------------------------
# 状态机
# ---------------------------------------------------------------------------

class Top:
    """活跃或已预备的顶层事务。"""

    __slots__ = ("xid", "prepared", "gid", "changes", "subs", "aborted")

    def __init__(self, xid):
        self.xid = xid
        self.prepared = False
        self.gid = None
        self.changes = []    # [(子事务 xid 或 None, 记录)]，按接收序
        self.subs = set()    # 全部直属子事务 xid
        self.aborted = set() # 已撤销的子事务 xid


class Processor:
    def __init__(self):
        self.relations = {}   # oid -> (列数, R 原文 hex)，全局缓存，回滚不撤销
        self.tops = {}        # xid -> Top（活跃或已预备）
        self.sub_owner = {}   # 子事务 xid -> 所属顶层 xid
        self.dead = set()     # 已终结 xid（顶层及其子事务），禁止复用
        self.seg = None       # 打开的段：(顶层 xid, S 的消息号)
        self.out = []         # 按提交序的 {"xid", "changes"}
        self.i = 0            # 当前消息号

    def reject(self):
        raise Reject(self.i)

    def classify(self, xid):
        """段内消息 xid 归当前顶层（返回 None）或为其直属子事务（返回该 xid）。

        未知 xid 绑定为当前顶层的直属子事务；已终结、他属顶层、他属子事务、
        已撤销子事务一律拒绝。保证无更深嵌套。
        """
        top_xid = self.seg[0]
        if xid == top_xid:
            return None
        if xid in self.dead or xid in self.tops:
            self.reject()
        owner = self.sub_owner.get(xid)
        if owner is None:
            top = self.tops[top_xid]
            top.subs.add(xid)
            self.sub_owner[xid] = top_xid
            return xid
        if owner != top_xid or xid in self.tops[top_xid].aborted:
            self.reject()
        return xid

    def terminate(self, xid):
        top = self.tops.pop(xid)
        self.dead.add(xid)
        for s in top.subs:
            self.dead.add(s)
            del self.sub_owner[s]
        return top

    def active_top(self, xid):
        top = self.tops.get(xid)
        if top is None or top.prepared:
            self.reject()
        return top

    def commit(self, top):
        changes = [rec for sub, rec in top.changes
                   if sub is None or sub not in top.aborted]
        self.out.append({"xid": top.xid, "changes": changes})
        self.terminate(top.xid)

    # -- 消息应用：tag 与 fields 来自 parse_message，item 为输入原文 --

    def apply(self, tag, f, item):
        if tag == "S":
            xid, first = f
            if self.seg is not None:            # 段不嵌套
                self.reject()
            if xid in self.dead or xid in self.sub_owner:
                self.reject()
            top = self.tops.get(xid)
            if top is None:
                if first != 1:                  # 首段标志须为 1
                    self.reject()
                self.tops[xid] = Top(xid)
            else:
                if top.prepared or first != 0:  # 后续段标志须为 0
                    self.reject()
            self.seg = (xid, self.i)

        elif tag == "E":
            if self.seg is None:
                self.reject()
            self.seg = None

        elif tag == "R":
            xid, oid, ncols = f
            if self.seg is None:                # R 仅段内
                self.reject()
            self.classify(xid)
            self.relations[oid] = (ncols, item)  # 全局 OID 缓存，回滚不撤销

        elif tag in ("I", "U", "D"):
            xid, oid, old, new = f
            if self.seg is None:                # DML 仅段内
                self.reject()
            sub = self.classify(xid)
            rel = self.relations.get(oid)       # 固定当时最近的 R
            if rel is None:
                self.reject()
            ncols, rhex = rel
            for t in (old, new):
                if t is not None and len(t) != ncols:
                    self.reject()
            top = self.tops[self.seg[0]]
            top.changes.append((sub, [self.i, tag, rhex, old, new]))

        elif tag == "c":                        # 流式提交
            if self.seg is not None:            # 仅段外
                self.reject()
            self.commit(self.active_top(f[0]))

        elif tag == "A":                        # 流式撤销
            xid, sub = f
            if self.seg is not None:
                self.reject()
            top = self.active_top(xid)
            if sub == xid:                      # 两 XID 相同：撤销整体
                self.terminate(xid)
            else:                               # 撤销指定子事务 DML 并禁再引用
                if sub in self.dead or sub in self.tops:
                    self.reject()
                owner = self.sub_owner.get(sub)
                if owner is None:               # 未知子 XID：绑定后撤销
                    top.subs.add(sub)
                    self.sub_owner[sub] = xid
                elif owner != xid or sub in top.aborted:
                    self.reject()
                top.aborted.add(sub)

        elif tag == "p":                        # 预备
            if self.seg is not None:
                self.reject()
            top = self.active_top(f[4])
            top.prepared = True
            top.gid = f[5]

        elif tag in ("K", "r"):                 # 提交/回滚已预备事务
            if self.seg is not None:
                self.reject()
            top = self.tops.get(f[4])
            if top is None or not top.prepared or top.gid != f[5]:
                self.reject()                   # 仅匹配 XID 与 GID
            if tag == "K":
                self.commit(top)
            else:
                self.terminate(top.xid)

    def finish(self):
        if self.seg is not None:                # 未闭合段：报打开它的 S
            raise Reject(self.seg[1])
        return self.out


# ---------------------------------------------------------------------------
# 驱动
# ---------------------------------------------------------------------------

def run(items):
    """处理 hex 字符串列表，返回按提交序的 [{"xid", "changes"}]；出错抛 Reject。"""
    proc = Processor()
    for i, item in enumerate(items):
        if len(item) % 2 or not _HEX_RE.fullmatch(item):
            raise Reject(i)
        proc.i = i
        tag, fields = parse_message(bytes.fromhex(item), i)
        proc.apply(tag, fields, item)
    return proc.finish()


def main(argv):
    if len(argv) != 3:
        print("usage: repcollect.py INPUT OUTPUT", file=sys.stderr)
        return 2
    inp, outp = argv[1], argv[2]
    try:
        with open(inp, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print("repcollect: cannot read input: %s" % exc, file=sys.stderr)
        return 2
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError("top level must be an array of strings")
    except ValueError:
        print("$", file=sys.stderr)             # JSON 级错误
        return 1
    try:
        out = run(data)
    except Reject as exc:
        print(exc.index, file=sys.stderr)       # 出错消息的零基消息号
        return 1
    tmp = "%s.tmp.%d" % (outp, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, outp)                   # 成功才替换旧输出
    except OSError as exc:
        print("repcollect: cannot write output: %s" % exc, file=sys.stderr)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
