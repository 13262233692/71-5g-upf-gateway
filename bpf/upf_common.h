#ifndef __UPF_COMMON_H
#define __UPF_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define GTPU_PORT 2152
#define GTPU_VERSION 1
#define GTPU_PROTOCOL_TYPE 1

#define MAX_PDRS 10000
#define MAX_TEID_ENTRIES 10000

#define ETH_ALEN 6
#define IP_ALEN 4

struct gtpu_header {
    __u8 flags;
    __u8 message_type;
    __be16 length;
    __be32 teid;
} __attribute__((packed));

struct gtpu_ext_header {
    __u8 ext_len;
    __u8 ext_type;
    __u8 ext_value[0];
} __attribute__((packed));

struct pdr_key {
    __be32 teid;
} __attribute__((packed));

struct pdr_value {
    __u8 dst_mac[ETH_ALEN];
    __u32 ifindex;
    __u8 qfi;
    __u8 action;
    __be32 sdf_filter;
} __attribute__((packed));

struct session_info {
    __be32 ue_ip;
    __be32 upf_ip;
    __be32 teid_ul;
    __be32 teid_dl;
    __u8 ue_mac[ETH_ALEN];
    __u8 gnb_mac[ETH_ALEN];
} __attribute__((packed));

enum PDR_ACTION {
    PDR_ACTION_FORWARD = 0,
    PDR_ACTION_DROP = 1,
    PDR_ACTION_REDIRECT = 2,
};

struct stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 drop_packets;
    __u64 gtpu_packets;
    __u64 teid_miss;
    __u64 teid_hit;
};

#define GTPU_HEADER_LEN 8
#define GTPU_EXT_HEADER_MASK 0x04

static __always_inline __u16 gtpu_hdrlen(__u8 flags)
{
    __u16 len = GTPU_HEADER_LEN;
    if (flags & 0x03)
        len += 4;
    if (flags & GTPU_EXT_HEADER_MASK)
        len += 2;
    return len;
}

static __always_inline int is_gtpu_packet(struct udphdr *udph)
{
    return udph->dest == htons(GTPU_PORT) || udph->source == htons(GTPU_PORT);
}

#endif
