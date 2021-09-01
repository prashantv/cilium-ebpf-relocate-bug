// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/func")
int BPF_KPROBE(uprobe) {
  bpf_printk("UPROBE ENTRY probe triggered, ctx->sp: %x\n", PT_REGS_SP(ctx));
  return 0;
}

SEC("uretprobe/func")
int BPF_KRETPROBE(uretprobe, int ret) {
  bpf_printk("UPROBE EXIT: return = %d\n", ret);
  return 0;
}
