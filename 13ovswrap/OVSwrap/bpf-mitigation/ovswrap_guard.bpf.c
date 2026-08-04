#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ovswrap_guard.h"

#define EMSGSIZE 90
#define NLA_HEADER_LEN 4U
#define NLA_TYPE_MASK 0x3fffU
#define NLMSG_HEADER_LEN 16U
#define GENL_HEADER_LEN 4U
#define OVS_HEADER_LEN 4U
#define INTERNAL_NLA_MAX 65535U
#define NETLINK_GENERIC 16U
#define MAX_TOP_ATTRS 16U
#define MAX_ACTION_DEPTH 16U
#define FRAME_COUNT 32U
#define MAX_PARSE_TRANSITIONS 32768U
#define MAX_FULL_ACTION_LISTS 16U
#define MAX_DRIVER_TRANSITIONS \
	((MAX_PARSE_TRANSITIONS + MAX_TOP_ATTRS + 3U) * \
	 MAX_FULL_ACTION_LISTS + 1U)
#define NLM_F_REQUEST 1U

#define OVS_FLOW_CMD_NEW 1U
#define OVS_FLOW_CMD_SET 4U
#define OVS_PACKET_CMD_EXECUTE 3U
#define OVS_FLOW_ATTR_ACTIONS 2U
#define OVS_PACKET_ATTR_ACTIONS 3U
#define OVS_ACTION_ATTR_SET 3U
#define OVS_ACTION_ATTR_SAMPLE 6U
#define OVS_ACTION_ATTR_CT 12U
#define OVS_ACTION_ATTR_CLONE 20U
#define OVS_ACTION_ATTR_CHECK_PKT_LEN 21U
#define OVS_ACTION_ATTR_DEC_TTL 23U
#define OVS_KEY_ATTR_TUNNEL 16U
#define OVS_SAMPLE_ATTR_PROBABILITY 1U
#define OVS_SAMPLE_ATTR_ACTIONS 2U
#define OVS_CHECK_PKT_LEN_ATTR_PKT_LEN 1U
#define OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER 2U
#define OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL 3U
#define OVS_DEC_TTL_ATTR_ACTION 1U

enum parse_result {
	PARSE_SAFE = 0,
	PARSE_BLOCK = 1,
	PARSE_UNCERTAIN = 2,
	PARSE_MORE = 3,
};

enum frame_kind {
	FRAME_ROOT = 0,
	FRAME_CLONE = 1,
	FRAME_SAMPLE = 2,
	FRAME_DEC_TTL = 3,
	FRAME_CHECK_PKT_LEN = 4,
};

enum frame_stage {
	STAGE_SCAN = 0,
	STAGE_ACTIONS = 1,
	STAGE_CHECK_LESSER = 2,
	STAGE_CHECK_GREATER = 3,
};

enum driver_phase {
	PHASE_MESSAGE = 0,
	PHASE_TOP_ATTRS = 1,
	PHASE_ACTIONS = 2,
};

struct sk_buff {
	unsigned int len;
	unsigned char *data;
} __attribute__((preserve_access_index));

struct sock {
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct nla_header {
	__u16 len;
	__u16 type;
};

struct nlmsg_header {
	__u32 len;
	__u16 type;
	__u16 flags;
	__u32 seq;
	__u32 pid;
};

struct parse_frame {
	__u32 cursor;
	__u32 end;
	__u32 generated_len;
	__u32 child1_start;
	__u32 child1_end;
	__u32 child2_start;
	__u32 child2_end;
	__u32 first_generated_len;
	__u8 kind;
	__u8 stage;
	__u8 seen;
};

struct parser_scratch {
	struct parse_frame frames[FRAME_COUNT];
	__u32 depth;
	__u32 message_start;
	__u32 message_end;
	__u32 next_message_start;
	__u32 top_cursor;
	__u32 actions_start;
	__u32 actions_end;
	__u32 wanted_attr;
	__u8 top_attrs_seen;
	__u8 found_actions;
	__u8 phase;
};

struct driver_callback_context {
	const unsigned char *data;
	const struct ovswrap_guard_config *config;
	struct parser_scratch *scratch;
	__u32 skb_len;
	int result;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ovswrap_guard_config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct parser_scratch);
} scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_DRIVER_TRANSITIONS);
	__type(key, __u32);
	__type(value, __u8);
} driver_transitions SEC(".maps");

static __always_inline __u32 align4(__u32 value)
{
	return (value + 3U) & ~3U;
}

static __always_inline int aligned_next(__u32 offset, __u32 length,
					 __u32 end, __u32 *next)
{
	__u32 aligned;

	if (length > 0xfffffffcU || offset > end)
		return -1;
	aligned = align4(length);
	if (aligned > end - offset)
		return -1;
	*next = offset + aligned;
	return 0;
}

static __always_inline int message_next(__u32 offset, __u32 length,
					__u32 end, __u32 *next)
{
	__u32 aligned;

	if (offset > end || length > end - offset)
		return -1;
	if (length > 0xfffffffcU)
		return -1;
	aligned = align4(length);
	if (aligned > end - offset) {
		*next = end;
		return 0;
	}
	*next = offset + aligned;
	return 0;
}

static __always_inline int read_bytes(const unsigned char *data, __u32 offset,
				      void *out, __u32 size)
{
	return bpf_probe_read_kernel(out, size, data + offset);
}

static __always_inline int read_nla(const unsigned char *data, __u32 offset,
				    __u32 end, struct nla_header *header)
{
	if (offset > end || end - offset < NLA_HEADER_LEN)
		return -1;
	if (read_bytes(data, offset, header, sizeof(*header)))
		return -1;
	if (header->len < NLA_HEADER_LEN || header->len > end - offset)
		return -1;
	return 0;
}

static __always_inline int add_generated(struct parse_frame *frame,
					 __u32 amount)
{
	if (frame->generated_len > 0xffffffffU - amount)
		return -1;
	frame->generated_len += amount;
	return 0;
}

static __always_inline int generated_set_size(
	const unsigned char *data, __u32 action_start, __u32 action_end,
	const struct ovswrap_guard_config *config, __u32 *generated)
{
	struct nla_header key;
	__u32 inner_start = action_start + NLA_HEADER_LEN;
	__u32 inner_total;
	__u32 key_len;
	__u32 type;

	if (read_nla(data, inner_start, action_end, &key))
		return -1;
	inner_total = align4(key.len);
	if (inner_start > action_end || inner_total != action_end - inner_start)
		return -1;
	type = key.type & NLA_TYPE_MASK;
	if (type == OVS_KEY_ATTR_TUNNEL) {
		*generated = NLA_HEADER_LEN +
			     align4(NLA_HEADER_LEN + config->tunnel_info_size);
		return 0;
	}
	key_len = key.len - NLA_HEADER_LEN;
	if (key_len > (0xffffffffU - NLA_HEADER_LEN) / 2U)
		return -1;
	*generated = NLA_HEADER_LEN +
		     align4(NLA_HEADER_LEN + key_len * 2U);
	return 0;
}

static __always_inline void init_container_frame(
	struct parse_frame *frame, __u32 type, __u32 start, __u32 end)
{
	frame->cursor = start;
	frame->end = end;
	frame->generated_len = 0;
	frame->child1_start = 0;
	frame->child1_end = 0;
	frame->child2_start = 0;
	frame->child2_end = 0;
	frame->first_generated_len = 0;
	frame->seen = 0;

	if (type == OVS_ACTION_ATTR_CLONE) {
		frame->kind = FRAME_CLONE;
		frame->stage = STAGE_ACTIONS;
	} else if (type == OVS_ACTION_ATTR_SAMPLE) {
		frame->kind = FRAME_SAMPLE;
		frame->stage = STAGE_SCAN;
	} else if (type == OVS_ACTION_ATTR_DEC_TTL) {
		frame->kind = FRAME_DEC_TTL;
		frame->stage = STAGE_SCAN;
	} else {
		frame->kind = FRAME_CHECK_PKT_LEN;
		frame->stage = STAGE_SCAN;
	}
}

static __always_inline int scan_wrapper_attr(
	const unsigned char *data, struct parse_frame *frame)
{
	struct nla_header attr;
	__u32 payload_start;
	__u32 next;
	__u32 type;
	__u8 bit;

	if (read_nla(data, frame->cursor, frame->end, &attr))
		return PARSE_UNCERTAIN;
	if (aligned_next(frame->cursor, attr.len, frame->end, &next))
		return PARSE_UNCERTAIN;
	payload_start = frame->cursor + NLA_HEADER_LEN;
	type = attr.type & NLA_TYPE_MASK;

	if (frame->kind == FRAME_SAMPLE) {
		if (type != OVS_SAMPLE_ATTR_PROBABILITY &&
		    type != OVS_SAMPLE_ATTR_ACTIONS)
			return PARSE_UNCERTAIN;
		bit = 1U << type;
		if (frame->seen & bit)
			return PARSE_UNCERTAIN;
		frame->seen |= bit;
		if (type == OVS_SAMPLE_ATTR_PROBABILITY) {
			if (attr.len != NLA_HEADER_LEN + sizeof(__u32))
				return PARSE_UNCERTAIN;
		} else {
			if (attr.len != NLA_HEADER_LEN &&
			    attr.len < NLA_HEADER_LEN * 2U)
				return PARSE_UNCERTAIN;
			frame->child1_start = payload_start;
			frame->child1_end = frame->cursor + attr.len;
		}
	} else if (frame->kind == FRAME_DEC_TTL) {
		if (!type)
			return PARSE_UNCERTAIN;
		if (type == OVS_DEC_TTL_ATTR_ACTION) {
			bit = 1U << type;
			if (frame->seen & bit)
				return PARSE_UNCERTAIN;
			frame->seen |= bit;
			if (attr.len != NLA_HEADER_LEN &&
			    attr.len < NLA_HEADER_LEN * 2U)
				return PARSE_UNCERTAIN;
			frame->child1_start = payload_start;
			frame->child1_end = frame->cursor + attr.len;
		}
	} else {
		if (type < OVS_CHECK_PKT_LEN_ATTR_PKT_LEN ||
		    type > OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL)
			return PARSE_UNCERTAIN;
		bit = 1U << type;
		frame->seen |= bit;
		if (type == OVS_CHECK_PKT_LEN_ATTR_PKT_LEN) {
			if (attr.len != NLA_HEADER_LEN + sizeof(__u16))
				return PARSE_UNCERTAIN;
		} else if (type ==
			   OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER) {
			frame->child2_start = payload_start;
			frame->child2_end = frame->cursor + attr.len;
		} else {
			frame->child1_start = payload_start;
			frame->child1_end = frame->cursor + attr.len;
		}
	}
	frame->cursor = next;
	return PARSE_SAFE;
}

static __always_inline int begin_wrapper_actions(struct parse_frame *frame)
{
	if (frame->kind == FRAME_SAMPLE) {
		if ((frame->seen & 0x6U) != 0x6U)
			return PARSE_UNCERTAIN;
		frame->stage = STAGE_ACTIONS;
	} else if (frame->kind == FRAME_DEC_TTL) {
		if (!(frame->seen & (1U << OVS_DEC_TTL_ATTR_ACTION)))
			return PARSE_UNCERTAIN;
		frame->stage = STAGE_ACTIONS;
	} else {
		if ((frame->seen & 0xeU) != 0xeU)
			return PARSE_UNCERTAIN;
		frame->stage = STAGE_CHECK_LESSER;
	}
	frame->cursor = frame->child1_start;
	frame->end = frame->child1_end;
	frame->generated_len = 0;
	return PARSE_SAFE;
}

static __always_inline int finish_container(
	struct parse_frame *frame, const struct ovswrap_guard_config *config,
	__u32 *container_len)
{
	__u64 total;

	if (frame->kind == FRAME_CLONE) {
		total = NLA_HEADER_LEN +
			align4(NLA_HEADER_LEN + sizeof(__u32)) +
			frame->generated_len;
	} else if (frame->kind == FRAME_SAMPLE) {
		total = NLA_HEADER_LEN +
			align4(NLA_HEADER_LEN + config->sample_arg_size) +
			frame->generated_len;
	} else if (frame->kind == FRAME_DEC_TTL) {
		if ((__u64)NLA_HEADER_LEN + frame->generated_len >
		    INTERNAL_NLA_MAX)
			return PARSE_BLOCK;
		total = NLA_HEADER_LEN * 2U + frame->generated_len;
	} else {
		if ((__u64)NLA_HEADER_LEN + frame->generated_len >
		    INTERNAL_NLA_MAX)
			return PARSE_BLOCK;
		total = NLA_HEADER_LEN * 3U +
			align4(NLA_HEADER_LEN + config->check_pkt_len_arg_size) +
			frame->first_generated_len + frame->generated_len;
	}
	if (total > INTERNAL_NLA_MAX)
		return PARSE_BLOCK;
	*container_len = align4((__u32)total);
	return PARSE_SAFE;
}

static __noinline int run_parser_step(
	const unsigned char *data, const struct ovswrap_guard_config *config,
	struct parser_scratch *scratch)
{
	struct parse_frame *frame;
	__u32 depth = scratch->depth;
	__u32 frame_index;
	int result;

	if (depth > MAX_ACTION_DEPTH)
		return PARSE_UNCERTAIN;

	frame_index = depth & (FRAME_COUNT - 1U);
	frame = &scratch->frames[frame_index];
	if (frame->stage == STAGE_SCAN) {
		if (frame->cursor != frame->end) {
			result = scan_wrapper_attr(data, frame);
			if (result != PARSE_SAFE)
				return result;
			return PARSE_MORE;
		}
		result = begin_wrapper_actions(frame);
		if (result != PARSE_SAFE)
			return result;
		return PARSE_MORE;
	}

	if (frame->cursor != frame->end) {
		struct nla_header action;
		struct parse_frame *child;
		__u32 action_start = frame->cursor;
		__u32 action_end;
		__u32 generated;
		__u32 next;
		__u32 type;

		if (read_nla(data, action_start, frame->end, &action))
			return PARSE_UNCERTAIN;
		action_end = action_start + action.len;
		if (aligned_next(action_start, action.len, frame->end, &next))
			return PARSE_UNCERTAIN;
		frame->cursor = next;
		type = action.type & NLA_TYPE_MASK;

		if (type == OVS_ACTION_ATTR_CLONE ||
		    type == OVS_ACTION_ATTR_SAMPLE ||
		    type == OVS_ACTION_ATTR_CHECK_PKT_LEN ||
		    type == OVS_ACTION_ATTR_DEC_TTL) {
			if (depth >= MAX_ACTION_DEPTH)
				return PARSE_UNCERTAIN;
			depth++;
			scratch->depth = depth;
			child = &scratch->frames[
				depth & (FRAME_COUNT - 1U)];
			init_container_frame(child, type,
					     action_start + NLA_HEADER_LEN,
					     action_end);
			return PARSE_MORE;
		}

		if (type == OVS_ACTION_ATTR_CT) {
			if (!config->conntrack_info_size)
				return PARSE_BLOCK;
			generated = align4(NLA_HEADER_LEN +
					   config->conntrack_info_size);
		} else if (type == OVS_ACTION_ATTR_SET) {
			if (generated_set_size(data, action_start, action_end,
					       config, &generated))
				return PARSE_UNCERTAIN;
			if (generated > INTERNAL_NLA_MAX)
				return PARSE_BLOCK;
		} else {
			generated = align4(action.len);
		}
		if (add_generated(frame, generated))
			return PARSE_UNCERTAIN;
		return PARSE_MORE;
	}

	if (frame->kind == FRAME_ROOT)
		return PARSE_SAFE;

	if (frame->kind == FRAME_CHECK_PKT_LEN &&
	    frame->stage == STAGE_CHECK_LESSER) {
		if ((__u64)NLA_HEADER_LEN + frame->generated_len >
		    INTERNAL_NLA_MAX)
			return PARSE_BLOCK;
		frame->first_generated_len = frame->generated_len;
		frame->generated_len = 0;
		frame->cursor = frame->child2_start;
		frame->end = frame->child2_end;
		frame->stage = STAGE_CHECK_GREATER;
		return PARSE_MORE;
	}

	{
		struct parse_frame *parent;
		__u32 container_len;

		result = finish_container(frame, config, &container_len);
		if (result != PARSE_SAFE)
			return result;
		depth--;
		scratch->depth = depth;
		parent = &scratch->frames[depth & (FRAME_COUNT - 1U)];
		if (add_generated(parent, container_len))
			return PARSE_UNCERTAIN;
	}
	return PARSE_MORE;
}

static __always_inline void init_root_frame(struct parser_scratch *scratch,
					    __u32 start, __u32 end,
					    __u32 next_message_start)
{
	struct parse_frame *frame = &scratch->frames[0];

	frame->cursor = start;
	frame->end = end;
	frame->generated_len = 0;
	frame->child1_start = 0;
	frame->child1_end = 0;
	frame->child2_start = 0;
	frame->child2_end = 0;
	frame->first_generated_len = 0;
	frame->kind = FRAME_ROOT;
	frame->stage = STAGE_ACTIONS;
	frame->seen = 0;
	scratch->depth = 0;
	scratch->next_message_start = next_message_start;
}

static __noinline int run_driver_step(
	const unsigned char *data, __u32 skb_len,
	const struct ovswrap_guard_config *config, struct parser_scratch *scratch)
{
	if (scratch->phase == PHASE_ACTIONS) {
		int result = run_parser_step(data, config, scratch);

		if (result != PARSE_SAFE)
			return result;
		scratch->message_start = scratch->next_message_start;
		scratch->phase = PHASE_MESSAGE;
		return PARSE_MORE;
	}

	if (scratch->phase == PHASE_TOP_ATTRS) {
		struct nla_header attr;
		__u32 next;

		if (scratch->top_cursor == scratch->message_end) {
			if (scratch->found_actions) {
				init_root_frame(scratch, scratch->actions_start,
						scratch->actions_end,
						scratch->next_message_start);
				scratch->phase = PHASE_ACTIONS;
			} else {
				scratch->message_start =
					scratch->next_message_start;
				scratch->phase = PHASE_MESSAGE;
			}
			return PARSE_MORE;
		}
		if (scratch->top_attrs_seen >= MAX_TOP_ATTRS)
			return PARSE_UNCERTAIN;
		if (read_nla(data, scratch->top_cursor, scratch->message_end,
			     &attr))
			return PARSE_UNCERTAIN;
		if (aligned_next(scratch->top_cursor, attr.len,
				 scratch->message_end, &next))
			return PARSE_UNCERTAIN;
		if ((attr.type & NLA_TYPE_MASK) == scratch->wanted_attr) {
			scratch->actions_start =
				scratch->top_cursor + NLA_HEADER_LEN;
			scratch->actions_end =
				scratch->top_cursor + attr.len;
			scratch->found_actions = 1;
		}
		scratch->top_cursor = next;
		scratch->top_attrs_seen++;
		return PARSE_MORE;
	}

	{
		struct nlmsg_header header;
		__u8 command;

		if (scratch->message_start == skb_len)
			return PARSE_SAFE;
		if (scratch->message_start > skb_len)
			return PARSE_UNCERTAIN;
		if (skb_len - scratch->message_start < NLMSG_HEADER_LEN)
			return PARSE_SAFE;
		if (read_bytes(data, scratch->message_start, &header,
			       sizeof(header)))
			return PARSE_UNCERTAIN;
		if (header.len < NLMSG_HEADER_LEN ||
		    header.len > skb_len - scratch->message_start)
			return PARSE_SAFE;
		scratch->message_end = scratch->message_start + header.len;
		if (message_next(scratch->message_start, header.len, skb_len,
				 &scratch->next_message_start))
			return PARSE_UNCERTAIN;

		if (!(header.flags & NLM_F_REQUEST) ||
		    header.len < NLMSG_HEADER_LEN + GENL_HEADER_LEN +
				 OVS_HEADER_LEN ||
		    (header.type != config->flow_family &&
		     header.type != config->packet_family)) {
			scratch->message_start = scratch->next_message_start;
			return PARSE_MORE;
		}
		if (read_bytes(data,
			       scratch->message_start + NLMSG_HEADER_LEN,
			       &command, sizeof(command)))
			return PARSE_UNCERTAIN;
		if (header.type == config->flow_family &&
		    (command == OVS_FLOW_CMD_NEW || command == OVS_FLOW_CMD_SET))
			scratch->wanted_attr = OVS_FLOW_ATTR_ACTIONS;
		else if (header.type == config->packet_family &&
			 command == OVS_PACKET_CMD_EXECUTE)
			scratch->wanted_attr = OVS_PACKET_ATTR_ACTIONS;
		else {
			scratch->message_start = scratch->next_message_start;
			return PARSE_MORE;
		}

		scratch->top_cursor = scratch->message_start +
				      NLMSG_HEADER_LEN + GENL_HEADER_LEN +
				      OVS_HEADER_LEN;
		scratch->actions_start = 0;
		scratch->actions_end = 0;
		scratch->top_attrs_seen = 0;
		scratch->found_actions = 0;
		scratch->phase = PHASE_TOP_ATTRS;
		return PARSE_MORE;
	}
}

static long run_driver_callback(void *map, const __u32 *key, __u8 *value,
				struct driver_callback_context *context)
{
	(void)map;
	(void)key;
	(void)value;

	context->result = run_driver_step(context->data, context->skb_len,
					  context->config,
					  context->scratch);
	return context->result == PARSE_MORE ? 0 : 1;
}

static __noinline int run_driver(const unsigned char *data, __u32 skb_len,
				 const struct ovswrap_guard_config *config,
				 struct parser_scratch *scratch)
{
	struct driver_callback_context context = {
		.data = data,
		.config = config,
		.scratch = scratch,
		.skb_len = skb_len,
		.result = PARSE_MORE,
	};

	bpf_for_each_map_elem(&driver_transitions, run_driver_callback,
			      &context, 0);
	return context.result;
}

SEC("lsm/netlink_send")
int BPF_PROG(ovswrap_netlink_send, struct sock *sk, struct sk_buff *skb, int ret)
{
	const struct ovswrap_guard_config *config;
	struct parser_scratch *scratch;
	const unsigned char *data;
	__u32 skb_len;
	__u32 zero = 0;
	int result;

	(void)ctx;
	if (ret)
		return ret;
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != NETLINK_GENERIC)
		return 0;
	config = bpf_map_lookup_elem(&config_map, &zero);
	if (!config || !config->flow_family || !config->packet_family ||
	    !config->sample_arg_size || !config->check_pkt_len_arg_size ||
	    !config->tunnel_info_size)
		return 0;

	skb_len = BPF_CORE_READ(skb, len);
	data = BPF_CORE_READ(skb, data);
	if (!data || skb_len < NLMSG_HEADER_LEN)
		return 0;
	scratch = bpf_map_lookup_elem(&scratch_map, &zero);
	if (!scratch)
		return -EMSGSIZE;
	scratch->message_start = 0;
	scratch->phase = PHASE_MESSAGE;
	result = run_driver(data, skb_len, config, scratch);
	if (result == PARSE_SAFE)
		return 0;
	return -EMSGSIZE;
}

char LICENSE[] SEC("license") = "GPL";
