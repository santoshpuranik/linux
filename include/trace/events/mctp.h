/* SPDX-License-Identifier: GPL-2.0 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mctp

#if !defined(_TRACE_MCTP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MCTP_H

#include <linux/tracepoint.h>

#ifndef __TRACE_MCTP_ENUMS
#define __TRACE_MCTP_ENUMS
enum {
	MCTP_TRACE_KEY_TIMEOUT,
	MCTP_TRACE_KEY_REPLIED,
	MCTP_TRACE_KEY_INVALIDATED,
	MCTP_TRACE_KEY_CLOSED,
	MCTP_TRACE_KEY_DROPPED,
};
#endif /* __TRACE_MCTP_ENUMS */

TRACE_DEFINE_ENUM(MCTP_TRACE_KEY_TIMEOUT);
TRACE_DEFINE_ENUM(MCTP_TRACE_KEY_REPLIED);
TRACE_DEFINE_ENUM(MCTP_TRACE_KEY_INVALIDATED);
TRACE_DEFINE_ENUM(MCTP_TRACE_KEY_CLOSED);
TRACE_DEFINE_ENUM(MCTP_TRACE_KEY_DROPPED);

TRACE_EVENT(mctp_key_acquire,
	TP_PROTO(const struct mctp_sk_key *key),
	TP_ARGS(key),
	TP_STRUCT__entry(
		__field(__u8,	paddr)
		__field(__u8,	laddr)
		__field(__u8,	tag)
	),
	TP_fast_assign(
		__entry->paddr = key->peer_addr;
		__entry->laddr = key->local_addr;
		__entry->tag = key->tag;
	),
	TP_printk("local %d, peer %d, tag %1x",
		__entry->laddr,
		__entry->paddr,
		__entry->tag
	)
);

TRACE_EVENT(mctp_key_release,
	TP_PROTO(const struct mctp_sk_key *key, int reason),
	TP_ARGS(key, reason),
	TP_STRUCT__entry(
		__field(__u8,	paddr)
		__field(__u8,	laddr)
		__field(__u8,	tag)
		__field(int,	reason)
	),
	TP_fast_assign(
		__entry->paddr = key->peer_addr;
		__entry->laddr = key->local_addr;
		__entry->tag = key->tag;
		__entry->reason = reason;
	),
	TP_printk("local %d, peer %d, tag %1x %s",
		__entry->laddr,
		__entry->paddr,
		__entry->tag,
		__print_symbolic(__entry->reason,
				 { MCTP_TRACE_KEY_TIMEOUT, "timeout" },
				 { MCTP_TRACE_KEY_REPLIED, "replied" },
				 { MCTP_TRACE_KEY_INVALIDATED, "invalidated" },
				 { MCTP_TRACE_KEY_CLOSED, "closed" },
				 { MCTP_TRACE_KEY_DROPPED, "dropped" })
	)
);

TRACE_EVENT(mctp_i2c_tx_flow_lock,
	TP_PROTO(int fs, int lcount, int rcount, __u8 src, __u8 dst, __u8 tag),
	TP_ARGS(fs, lcount, rcount, src, dst, tag),
	TP_STRUCT__entry(
		__field(int,	fs)
		__field(int,	lcount)
		__field(int,	rcount)
		__field(__u8,	src)
		__field(__u8,	dst)
		__field(__u8,	tag)
	),
	TP_fast_assign(
		__entry->fs = fs;
		__entry->lcount = lcount;
		__entry->rcount = rcount;
		__entry->src = src;
		__entry->dst = dst;
		__entry->tag = tag;
	),
	TP_printk("fs %s, new lcount %d, rcount %d, key {%d -> %d, tag %1x}",
		  __print_symbolic(__entry->fs,
				   { 0, "invalid" },
				   { 1, "none" },
				   { 2, "new" },
				   { 3, "existing" }),
		  __entry->lcount, __entry->rcount,
		  __entry->src, __entry->dst, __entry->tag)
);

TRACE_EVENT(mctp_i2c_tx_flow_unlock,
	TP_PROTO(int fs, int lcount, int rcount, __u8 src, __u8 dst, __u8 tag),
	TP_ARGS(fs, lcount, rcount, src, dst, tag),
	TP_STRUCT__entry(
		__field(int,	fs)
		__field(int,	lcount)
		__field(int,	rcount)
		__field(__u8,	src)
		__field(__u8,	dst)
		__field(__u8,	tag)
	),
	TP_fast_assign(
		__entry->fs = fs;
		__entry->lcount = lcount;
		__entry->rcount = rcount;
		__entry->src = src;
		__entry->dst = dst;
		__entry->tag = tag;
	),
	TP_printk("fs %s, new lcount %d, rcount %d, key {%d -> %d, tag %1x}",
		  __print_symbolic(__entry->fs,
				   { 0, "invalid" },
				   { 1, "none" },
				   { 2, "new" },
				   { 3, "existing" }),
		  __entry->lcount, __entry->rcount,
		  __entry->src, __entry->dst, __entry->tag)
);

TRACE_EVENT(mctp_i2c_tx_flow_release,
	TP_PROTO(int dfs, int lcount, int rcount, __u8 src, __u8 dst, __u8 tag),
	TP_ARGS(dfs, lcount, rcount, src, dst, tag),
	TP_STRUCT__entry(
		__field(int,	dfs)
		__field(int,	lcount)
		__field(int,	rcount)
		__field(__u8,	src)
		__field(__u8,	dst)
		__field(__u8,	tag)
	),
	TP_fast_assign(
		__entry->dfs = dfs;
		__entry->lcount = lcount;
		__entry->rcount = rcount;
		__entry->src = src;
		__entry->dst = dst;
		__entry->tag = tag;
	),
	TP_printk("dfs %s, lcount %d, new rcount %d, key {%d -> %d, tag %1x}",
		  __print_symbolic(__entry->dfs,
				   { 0, "d:new" },
				   { 1, "d:active" },
				   { 2, "d:invalid" }),
		  __entry->lcount, __entry->rcount,
		  __entry->src, __entry->dst, __entry->tag)
);

TRACE_EVENT(mctp_i2c_tx_flow_release_dec,
	TP_PROTO(int lcount, int rcount),
	TP_ARGS(lcount, rcount),
	TP_STRUCT__entry(
		__field(int,	lcount)
		__field(int,	rcount)
	),
	TP_fast_assign(
		__entry->lcount = lcount;
		__entry->rcount = rcount;
	),
	TP_printk("new lcount %d, rcount %d",
		   __entry->lcount, __entry->rcount)
);

#endif

#include <trace/define_trace.h>
