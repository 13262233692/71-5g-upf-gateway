#ifndef __UPF_COMMON_H
#define __UPF_COMMON_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/spinlock.h>

#define GTPU_PORT 2152
#define GTPU_VERSION 1
#define GTPU_PROTOCOL_TYPE 1

#define MAX_PDRS 10000
#define MAX_TEID_ENTRIES 10000

#define ETH_ALEN 6
#define IP_ALEN 4

#define PDR_MAGIC 0x50445255
#define PDR_RETRY_MAX 3

#define TORN_READ_DETECT
#define SPIN_LOCK_ENABLED

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
    struct bpf_spin_lock lock;
    __u32 magic;
    __u32 version;
    __u8 dst_mac[ETH_ALEN];
    __u32 ifindex;
    __u8 qfi;
    __u8 action;
    __be32 sdf_filter;
    __u32 checksum;
    __u32 reserved;
} __attribute__((packed));

struct pdr_value_snapshot {
    __u32 magic;
    __u32 version;
    __u8 dst_mac[ETH_ALEN];
    __u32 ifindex;
    __u8 qfi;
    __u8 action;
    __be32 sdf_filter;
    __u32 checksum;
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
    __u64 torn_read_detected;
    __u64 spin_lock_contention;
    __u64 pdr_update_retries;
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

static __always_inline __u32 pdr_calc_checksum(struct pdr_value_snapshot *pdr)
{
    __u32 *data = (__u32 *)pdr;
    __u32 sum = 0;
    __u32 i;

    for (i = 0; i < (sizeof(*pdr) - sizeof(pdr->checksum)) / sizeof(__u32); i++) {
        sum += data[i];
        sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    }

    return ~sum;
}

static __always_inline int pdr_verify_integrity(struct pdr_value_snapshot *pdr)
{
    if (pdr->magic != PDR_MAGIC)
        return 0;

    __u32 calc_checksum = pdr_calc_checksum(pdr);
    if (calc_checksum != pdr->checksum)
        return 0;

    return 1;
}

static __always_inline void pdr_init_checksum(struct pdr_value *pdr)
{
    pdr->magic = PDR_MAGIC;
    pdr->version = 1;

    struct pdr_value_snapshot snap;
    __builtin_memcpy(&snap.magic, &pdr->magic, sizeof(snap));
    snap.checksum = 0;
    pdr->checksum = pdr_calc_checksum(&snap);
}

static __always_inline void pdr_update_checksum(struct pdr_value *pdr)
{
    pdr->version++;

    struct pdr_value_snapshot snap;
    __builtin_memcpy(&snap.magic, &pdr->magic, sizeof(snap));
    snap.checksum = 0;
    pdr->checksum = pdr_calc_checksum(&snap);
}

#endif
