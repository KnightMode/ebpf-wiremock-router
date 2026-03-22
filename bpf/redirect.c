// SPDX-License-Identifier: GPL-2.0
// eBPF program to transparently redirect ALL outgoing TCP connections to a
// local proxy. The proxy inspects the HTTP Host header (or TLS SNI) and
// routes to the correct WireMock port or passes through to the real server.
//
// This approach mirrors how Keploy works: intercept everything at the
// syscall level, let a userspace proxy make routing decisions.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET     2
#define SOCK_STREAM 1

// PID of the proxy process — its connections must NOT be intercepted
// (otherwise we get an infinite redirect loop)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} proxy_pid_map SEC(".maps");

// Port the proxy listens on (stored in ctx->user_port format, i.e.
// network-byte-order bytes interpreted as native-endian __u16)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} proxy_port_map SEC(".maps");

// Stats counters: 0 = total outgoing connects seen, 1 = redirected to proxy
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("cgroup/connect4")
int connect4_redirect(struct bpf_sock_addr *ctx)
{
    // Only handle IPv4 TCP (skip UDP — DNS, etc.)
    if (ctx->family != AF_INET)
        return 1;
    if (ctx->type != SOCK_STREAM)
        return 1;

    // Skip connections to any loopback address (127.0.0.0/8).
    // This covers WireMock, metadata API, the proxy's backend connections,
    // and Docker's internal DNS at 127.0.0.11.
    __u32 dst = bpf_ntohl(ctx->user_ip4);
    if ((dst >> 24) == 127)
        return 1;

    // Skip connections from the proxy process itself (prevent loops)
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 zero = 0;
    __u32 *ppid = bpf_map_lookup_elem(&proxy_pid_map, &zero);
    if (ppid && *ppid == pid)
        return 1;

    // Bump total connection counter
    __u64 *total = bpf_map_lookup_elem(&stats_map, &zero);
    if (total)
        __sync_fetch_and_add(total, 1);

    // Look up the proxy port
    __u32 *pport = bpf_map_lookup_elem(&proxy_port_map, &zero);
    if (!pport)
        return 1;

    // Redirect: rewrite destination to 127.0.0.1:<proxy_port>
    ctx->user_ip4  = bpf_htonl(0x7f000001);
    ctx->user_port = (__u16)*pport;

    // Bump redirected counter
    __u32 one = 1;
    __u64 *redir = bpf_map_lookup_elem(&stats_map, &one);
    if (redir)
        __sync_fetch_and_add(redir, 1);

    return 1;
}

char _license[] SEC("license") = "GPL";
