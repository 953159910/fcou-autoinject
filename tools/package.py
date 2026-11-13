#!/usr/bin/env python3
"""把模块目录打成可刷入的 zip（条目顺序固定，方便 diff）"""
import os
import sys
import zipfile

ORDER = [
    "module.prop",
    "post-fs-data.sh",
    "service.sh",
    "settings.conf",
    "inject-now.sh",
    "webui-start.sh",
    "webroot/index.html",
    "bin/fcou-inject",
    "payload/libForceCloseOreUI.so",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
]


def main() -> int:
    if len(sys.argv) != 3:
        print("用法: package.py <模块目录> <输出zip>", file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    files = [f for f in ORDER if os.path.isfile(os.path.join(src, f))]
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in files:
            z.write(os.path.join(src, f), f)
    print(f"{dst}: {len(files)} 个文件, {os.path.getsize(dst)} 字节")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
