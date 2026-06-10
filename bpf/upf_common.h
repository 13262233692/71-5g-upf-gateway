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
#define MAX_QOS_FLOWS 1024

#define ETH_ALEN 6
#define IP_ALEN 4

#define PDR_MAGIC 0x50445255
#define PDR_RETRY_MAX 3

#define TORN_READ_DETECT
#define SPIN_LOCK_ENABLED

#define QOS_MAGIC 0x514F5300

#define QFI_VOVR   1
#define QFI_VIDEO  2
#define QFI_IMS    5
#define QFI_EMBMS  7
#define QFI_DEFAULT 9

#define QOS_PRIORITY_VOVR    1
#define QOS_PRIORITY_VIDEO   3
#define QOS_PRIORITY_IMS     5
#define QOS_PRIORITY_DEFAULT 7

#define TOKEN_BUCKET_BURST_SCALE 8

enum QOS_FLOW_TYPE {
    QOS_FLOW_GBR    = 0,
    QOS_FLOW_NON_GBR = 1,
};

enum QOS_ACTION {
    QOS_ACTION_PASS = 0,
    QOS_ACTION_MARK = 1,
    QOS_ACTION_SHAP = 2,
    QOS_ACTION_DROP = 3,
};

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

struct token_bucket {
    __u64 tokens;
    __u64 last_update_ns;
    __u64 rate_bps;
    __u64 burst_size;
    __u32 magic;
    __u32 reserved;
} __attribute__((packed));

struct qos_flow_key {
    __u32 teid;
    __u8 qfi;
    __u8 padding[3];
} __attribute__((packed));

struct qos_flow_value {
    struct bpf_spin_lock lock;
    __u32 magic;
    __u8 qfi;
    __u8 flow_type;
    __u8 priority;
    __u8 action;
    __u64 gbr_bps;
    __u64 mbr_bps;
    struct token_bucket bucket_gbr;
    struct token_bucket bucket_mbr;
    __u64 total_bytes;
    __u64 dropped_bytes;
    __u64 shaped_packets;
} __attribute__((packed));

struct qos_flow_snapshot {
    __u32 magic;
    __u8 qfi;
    __u8 flow_type;
    __u8 priority;
    __u8 action;
    __u64 gbr_bps;
    __u64 mbr_bps;
    __u64 bucket_gbr_tokens;
    __u64 bucket_mbr_tokens;
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
    __u64 qos_shaped_packets;
    __u64 qos_dropped_gbr_exceed;
    __u64 qos_dropped_mbr_exceed;
    __u64 qos_vonr_protected;
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

static __always_inline void token_bucket_refill(struct token_bucket *tb,
                                                __u64 now_ns)
{
    if (tb->rate_bps == 0)
        return;

    __u64 elapsed = now_ns - tb->last_update_ns;
    if (elapsed > 0 && tb->last_update_ns > 0) {
        __u64 new_tokens = (elapsed * tb->rate_bps) / 1000000000ULL;
        __u64 total = tb->tokens + new_tokens;
        if (total > tb->burst_size)
            total = tb->burst_size;
        tb->tokens = total;
    }

    tb->last_update_ns = now_ns;
}

static __always_inline int token_bucket_consume(struct token_bucket *tb,
                                                __u64 pkt_len_bytes,
                                                __u64 now_ns)
{
    token_bucket_refill(tb, now_ns);

    __u64 pkt_bits = pkt_len_bytes * TOKEN_BUCKET_BURST_SCALE;

    if (tb->tokens >= pkt_bits) {
        tb->tokens -= pkt_bits;
        return 1;
    }

    return 0;
}

static __always_inline __u8 gtpu_extract_qfi(struct gtpu_header *gtpu,
                                              void *data_end)
{
    if (!(gtpu->flags & GTPU_EXT_HEADER_MASK))
        return 0;

    void *ext_start = (void *)gtpu + GTPU_HEADER_LEN;

    if (gtpu->flags & 0x03) {
        ext_start += 4;
    }

    if (ext_start + 2 > data_end)
        return 0;

    __u8 ext_len = *((__u8 *)ext_start);
    __u8 ext_type = *((__u8 *)(ext_start + 1));

    if (ext_type == 0x85) {
        if (ext_start + 3 > data_end)
            return 0;
        __u8 pdu_session = *((__u8 *)(ext_start + 2));
        return pdu_session & 0x3F;
    }

    return 0;
}

static __always_inline __u8 qfi_to_priority(__u8 qfi)
{
    switch (qfi) {
        case QFI_VOVR:   return QOS_PRIORITY_VOVR;
        case QFI_VIDEO:  return QOS_PRIORITY_VIDEO;
        case QFI_IMS:    return QOS_PRIORITY_IMS;
        case QFI_EMBMS:  return 4;
        case QFI_DEFAULT: return QOS_PRIORITY_DEFAULT;
        default:         return QOS_PRIORITY_DEFAULT;
    }
}

#endif
