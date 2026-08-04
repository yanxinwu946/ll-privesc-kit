#ifndef OVSWRAP_GUARD_H
#define OVSWRAP_GUARD_H

#include <linux/types.h>

struct ovswrap_guard_config {
	__u32 flow_family;
	__u32 packet_family;
	__u32 conntrack_info_size;
	__u32 sample_arg_size;
	__u32 check_pkt_len_arg_size;
	__u32 tunnel_info_size;
};

#endif
