# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
V := 1
SRC_DIR := src
BUILD_DIR := build
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
#BPFTOOL ?= $(abspath ../tools/bpftool)
BPFTOOL ?= /usr/sbin/bpftool
LIBBPF_SRC := $(abspath vendor/libbpf/src)
LIBBPF_OBJ := $(abspath $(BUILD_DIR)/libbpf.a)

# Libxdp
LIBXDP_SRC := $(abspath vendor/xdp-tools/lib/libxdp)
XDPTOOLS_DIR := $(abspath vendor/xdp-tools)
LIBXDP_OBJ := $(abspath $(BUILD_DIR)/libxdp.a)

VMLINUX := vmlinux/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -Ivendor/xdp-tools/headers -I$(BUILD_DIR) -Ilibbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

CC_APR := $(shell apr-1-config --cflags --includes)
LD_APR := $(shell apr-1-config --link-ld)

APPS = xdpfilter

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(BUILD_DIR))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(BUILD_DIR) $(APPS)

$(BUILD_DIR) $(BUILD_DIR)/libbpf $(BUILD_DIR)/libxdp:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(BUILD_DIR)/libbpf
	$(call msg,LIBBPF,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build libxdp
$(LIBXDP_OBJ): $(wildcard $(LIBXDP_SRC)/*.[ch] $(LIBXDP_SRC)/Makefile) | $(BUILD_DIR)/libxdp
	$(call msg,LIBXDP,$@)
	$(Q)$(MAKE) -C $(XDPTOOLS_DIR) BUILD_STATIC_ONLY=1 OBJDIR=$(dir $@) DESTDIR=$(dir $@) libxdp

# Build BPF code
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(LIBBPF_OBJ) $(wildcard $(SRC_DIR)/%.h) $(VMLINUX) | $(BUILD_DIR)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o | $(BUILD_DIR)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(BUILD_DIR)/%.o,$(APPS)): %.o: %.skel.h

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(wildcard $(SRC_DIR)/%.h) | $(BUILD_DIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(CC_APR) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(BUILD_DIR)/%.o $(LIBXDP_OBJ) $(LIBBPF_OBJ) | $(BUILD_DIR)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(LD_APR) $^ -lelf -lz -lapr-1 -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
