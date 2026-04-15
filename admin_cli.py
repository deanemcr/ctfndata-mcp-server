#!/usr/bin/env python3
"""
Admin CLI for CTFNDATA MCP Server — manage users from the command line.

Usage (run on Railway via `railway run`):
    python admin_cli.py create <username> <password> [--admin]
    python admin_cli.py list
    python admin_cli.py delete <username>
    python admin_cli.py reset-password <username> <new_password>
    python admin_cli.py token <username>   # generate a 30-day token without login
"""

import os
import sys
import argparse
import datetime

import psycopg2
import psycopg2.extras
import bcrypt
import jwt as pyjwt

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_EXPIRY_DAYS = int(os.environ.get("JWT_EXPIRY_DAYS", "30"))


def get_db():
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL not set", file=sys.stderr)
        sys.exit(1)
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def cmd_create(args):
    password_hash = bcrypt.hashpw(args.password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) RETURNING id",
                (args.username, password_hash, args.admin),
            )
            uid = cur.fetchone()[0]
        print(f"Created user '{args.username}' (id={uid}, admin={args.admin})")
    except psycopg2.errors.UniqueViolation:
        print(f"ERROR: User '{args.username}' already exists", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


def cmd_list(args):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("SELECT id, username, is_admin, created_at, last_login FROM users ORDER BY id")
        rows = cur.fetchall()
    conn.close()

    if not rows:
        print("No users found.")
        return

    print(f"{'ID':<5} {'Username':<25} {'Admin':<7} {'Created':<20} {'Last Login':<20}")
    print("-" * 80)
    for r in rows:
        created = r["created_at"].strftime("%Y-%m-%d %H:%M") if r["created_at"] else "-"
        login = r["last_login"].strftime("%Y-%m-%d %H:%M") if r["last_login"] else "never"
        print(f"{r['id']:<5} {r['username']:<25} {str(r['is_admin']):<7} {created:<20} {login:<20}")


def cmd_delete(args):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username = %s", (args.username,))
        if cur.rowcount == 0:
            print(f"User '{args.username}' not found", file=sys.stderr)
            sys.exit(1)
    conn.close()
    print(f"Deleted user '{args.username}'")


def cmd_reset_password(args):
    password_hash = bcrypt.hashpw(args.new_password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET password_hash = %s WHERE username = %s", (password_hash, args.username))
        if cur.rowcount == 0:
            print(f"User '{args.username}' not found", file=sys.stderr)
            sys.exit(1)
    conn.close()
    print(f"Password reset for '{args.username}'")


def cmd_token(args):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("SELECT id, username, is_admin FROM users WHERE username = %s", (args.username,))
        row = cur.fetchone()
    conn.close()

    if not row:
        print(f"User '{args.username}' not found", file=sys.stderr)
        sys.exit(1)

    payload = {
        "sub": row["username"],
        "uid": row["id"],
        "admin": row["is_admin"],
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=JWT_EXPIRY_DAYS),
    }
    token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    print(f"Token for '{args.username}' (valid {JWT_EXPIRY_DAYS} days):")
    print(token)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTFNDATA MCP Server Admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a new user")
    p_create.add_argument("username")
    p_create.add_argument("password")
    p_create.add_argument("--admin", action="store_true", help="Grant admin privileges")
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="List all users")
    p_list.set_defaults(func=cmd_list)

    p_delete = sub.add_parser("delete", help="Delete a user")
    p_delete.add_argument("username")
    p_delete.set_defaults(func=cmd_delete)

    p_reset = sub.add_parser("reset-password", help="Reset a user's password")
    p_reset.add_argument("username")
    p_reset.add_argument("new_password")
    p_reset.set_defaults(func=cmd_reset_password)

    p_token = sub.add_parser("token", help="Generate a JWT token for a user")
    p_token.add_argument("username")
    p_token.set_defaults(func=cmd_token)

    args = parser.parse_args()
    args.func(args)
