VERSION ?= 1.1
# make 自带 CC=cc，`?=` 不会覆盖它，只在 CC 来自默认值时才换成 musl
ifeq ($(origin CC),default)
CC := musl-gcc
endif
CFLAGS  ?= -O2 -static -s -Wall
OUT     := build
PAYLOAD := third_party/libForceCloseOreUI.so

.PHONY: all injector module package clean

all: injector

# aarch64 静态二进制：Android 上没有 glibc，静态 musl 最省事
injector:
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $(OUT)/fcou-inject src/fcou-inject.c
	@echo "→ $(OUT)/fcou-inject"

# 组装成 Magisk / KernelSU 模块目录
module: injector
	@rm -rf $(OUT)/module
	@cp -r module $(OUT)/module
	@mkdir -p $(OUT)/module/bin $(OUT)/module/payload
	@cp $(OUT)/fcou-inject $(OUT)/module/bin/fcou-inject
	@cp $(PAYLOAD) $(OUT)/module/payload/libForceCloseOreUI.so
	@chmod 755 $(OUT)/module/bin/fcou-inject $(OUT)/module/*.sh
	@echo "→ $(OUT)/module"

package: module
	@python3 tools/package.py $(OUT)/module $(OUT)/fcou_autoinject-v$(VERSION).zip
	@echo "→ $(OUT)/fcou_autoinject-v$(VERSION).zip"

clean:
	rm -rf $(OUT)
