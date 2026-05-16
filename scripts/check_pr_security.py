#!/usr/bin/env python3
"""Security checks for PR modifications to feed files."""

import sys
import yaml
import subprocess
import argparse


def get_base_file_content(base_sha, filepath):
    """Get file content from the base branch."""
    try:
        result = subprocess.run(
            ["git", "show", f"{base_sha}:{filepath}"],
            capture_output=True, text=True, check=True
        )
        return yaml.safe_load(result.stdout)
    except (subprocess.CalledProcessError, yaml.YAMLError):
        return None


def check_modified_file(filepath, base_sha, author_email):
    """Check a modified file for unauthorized changes."""
    errors = []

    # Load current version
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            current = yaml.safe_load(f)
    except Exception as e:
        errors.append(f"无法解析当前文件 / Cannot parse current file {filepath}: {e}")
        return errors

    # Load base version
    original = get_base_file_content(base_sha, filepath)
    if original is None:
        return errors  # File didn't exist in base, treat as new

    if not isinstance(original, dict) or not isinstance(current, dict):
        return errors

    # Check ASN change
    orig_asn = str(original.get("asn", "")).upper()
    curr_asn = str(current.get("asn", "")).upper()
    if orig_asn and curr_asn and orig_asn != curr_asn:
        errors.append(
            f"🚨 ASN 被修改 ({orig_asn} → {curr_asn})，疑似劫持攻击！"
            f" / ASN changed from {orig_asn} to {curr_asn}, possible hijacking!"
        )

    # Check contact change
    orig_contact = original.get("contact", "").lower()
    curr_contact = current.get("contact", "").lower()
    if orig_contact and curr_contact and orig_contact != curr_contact:
        errors.append(
            f"🚨 联系邮箱被修改 ({orig_contact} → {curr_contact})！"
            f" / Contact email changed from {orig_contact} to {curr_contact}!"
        )

    # Check if modifier is the file owner
    if author_email and orig_contact:
        if author_email.lower() != orig_contact:
            errors.append(
                f"🚨 提交者 ({author_email}) 不是此文件的所有者 ({orig_contact})，未授权的修改！"
                f" / Author ({author_email}) is not the file owner ({orig_contact}), unauthorized modification!"
            )
    elif not author_email:
        errors.append(
            "🚨 无法确认提交者身份，修改已有文件需要身份验证！"
            " / Cannot verify author identity, modifying existing files requires authentication!"
        )

    return errors


def check_deleted_file(filepath, base_sha, author_email):
    """Check a deleted file for authorization."""
    errors = []

    original = get_base_file_content(base_sha, filepath)

    if original and isinstance(original, dict):
        orig_contact = original.get("contact", "").lower()
        orig_asn = original.get("asn", "")

        if author_email and orig_contact and author_email.lower() != orig_contact:
            errors.append(
                f"🚨 提交者 ({author_email}) 试图删除属于 {orig_contact} ({orig_asn}) 的文件！"
                f" / Author ({author_email}) is trying to delete a file owned by {orig_contact} ({orig_asn})!"
            )

    errors.append(
        f"🚨 检测到文件删除: {filepath}。删除操作需要管理员审核。"
        f" / File deletion detected: {filepath}. Requires admin review."
    )

    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PR Security Checks")
    parser.add_argument("--modified", nargs="*", default=[], help="Modified files")
    parser.add_argument("--deleted", nargs="*", default=[], help="Deleted files")
    parser.add_argument("--base-sha", required=True, help="Base branch SHA")
    parser.add_argument("--author-email", default=None, help="Commit author email")

    args = parser.parse_args()

    all_errors = []

    for filepath in args.modified:
        if not filepath.strip():
            continue
        print(f"🔍 安全检查 / Security check: {filepath}")
        errors = check_modified_file(filepath, args.base_sha, args.author_email)
        all_errors.extend(errors)

    for filepath in args.deleted:
        if not filepath.strip():
            continue
        print(f"🔍 安全检查（删除）/ Security check (deletion): {filepath}")
        errors = check_deleted_file(filepath, args.base_sha, args.author_email)
        all_errors.extend(errors)

    if all_errors:
        print(f"\n🚨 安全检查失败 / Security Check Failed:")
        for e in all_errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("\n✅ 安全检查通过 / Security Check Passed.")
        sys.exit(0)
