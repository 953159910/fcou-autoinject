#!/usr/bin/env python3
"""校验 build/ 下的产物：ELF 必须是 aarch64，模块 zip 必须包含关键文件"""
import glob
import struct
import sys
import zipfile

REQUIRED = [
    "module.prop", "service.sh", "settings.conf", "webroot/index.html",
    "bin/fcou-inject", "payload/libForceCloseOreUI.so",
    "META-INF/com/google/android/update-binary",
]


def main() -> int:
    data = open("build/fcou-inject", "rb").read()
    assert data[:4] == b"\x7fELF", "不是 ELF"
    machine = struct.unpack_from("<H", data, 18)[0]
    assert machine == 0xB7, f"架构不是 aarch64: {machine:#x}"

    zips = glob.glob("build/fcou_autoinject-v*.zip")
    assert zips, "没有生成模块 zip"
    names = zipfile.ZipFile(zips[0]).namelist()
    missing = [f for f in REQUIRED if f not in names]
    assert not missing, f"缺少: {missing}"

    print(f"产物 OK: fcou-inject {len(data)} 字节 (aarch64), {len(names)} 个条目")
    return 0


if __name__ == "__main__":
    sys.exit(main())
