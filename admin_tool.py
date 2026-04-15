#!/usr/bin/env python3
"""
MindVault 许可证管理工具（本地运行）
用法：
  python admin_tool.py create --count 5 --note "客户A"
  python admin_tool.py list
  python admin_tool.py revoke XXXX-XXXX-XXXX-XXXX
  python admin_tool.py unbind XXXX-XXXX-XXXX-XXXX
"""

import argparse
import os
import sys
import urllib.request
import urllib.error
import json

SERVER_URL    = os.environ.get("LICENCE_SERVER", "https://your-server.com")
ADMIN_SECRET  = os.environ.get("ADMIN_SECRET",   "change-this-in-production-!!!!")


def call(method: str, path: str, body=None):
    url = f"{SERVER_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Content-Type":    "application/json",
            "X-Admin-Secret":  ADMIN_SECRET,
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"连接失败: {e.reason}")
        sys.exit(1)


def cmd_create(args):
    result = call("POST", "/admin/create", {"count": args.count, "note": args.note})
    print(f"\n✓ 成功生成 {result['count']} 个许可证：\n")
    for k in result["keys"]:
        print(f"  {k}")
    print()


def cmd_list(args):
    result = call("GET", "/admin/list")
    licences = result["licences"]
    if not licences:
        print("暂无许可证")
        return
    print(f"\n{'密钥':<20} {'状态':<8} {'MAC绑定':<8} {'激活时间':<22} {'备注'}")
    print("-" * 80)
    for lic in licences:
        bound = "已绑定" if lic["mac_hash"] else "未激活"
        status = lic["status"]
        act = lic["activated_at"] or "-"
        note = lic["note"] or ""
        print(f"  {lic['key']:<20} {status:<8} {bound:<8} {act:<22} {note}")
    print()


def cmd_revoke(args):
    call("POST", f"/admin/revoke/{args.key}")
    print(f"✓ 许可证 {args.key} 已撤销")


def cmd_unbind(args):
    call("POST", f"/admin/unbind/{args.key}")
    print(f"✓ 许可证 {args.key} 已解绑，可在新机器上激活")


def main():
    parser = argparse.ArgumentParser(description="MindVault 许可证管理")
    sub = parser.add_subparsers(dest="cmd")

    p_create = sub.add_parser("create", help="生成许可证")
    p_create.add_argument("--count", type=int, default=1)
    p_create.add_argument("--note", default="")

    sub.add_parser("list", help="查看所有许可证")

    p_rev = sub.add_parser("revoke", help="撤销许可证")
    p_rev.add_argument("key")

    p_unb = sub.add_parser("unbind", help="解绑许可证（允许换机）")
    p_unb.add_argument("key")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    {"create": cmd_create, "list": cmd_list,
     "revoke": cmd_revoke, "unbind": cmd_unbind}[args.cmd](args)


if __name__ == "__main__":
    main()
