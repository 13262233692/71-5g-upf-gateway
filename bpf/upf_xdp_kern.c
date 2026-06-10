#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "upf_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TEID_ENTRIES);
    __type(key, struct pdr_key);
    __type(value, struct pdr_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} teid_pdr_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} upf_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} upf_forward_map SEC(".maps");

struct hdr_cursor {
    void *pos;
    void *end;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    return eth->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *ip = nh->pos;
    int hdrsize;

    if (nh->pos + sizeof(*ip) > data_end)
        return -1;

    hdrsize = ip->ihl * 4;
    if (hdrsize < sizeof(*ip))
        return -1;

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = ip;
    return ip->protocol;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
    struct udphdr *udp = nh->pos;
    int hdrsize = sizeof(*udp);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *udphdr = udp;
    return 0;
}

static __always_inline int parse_gtpuhdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct gtpu_header **gtpuhdr,
                                         __u16 *hdr_len)
{
    struct gtpu_header *gtpu = nh->pos;

    if (nh->pos + GTPU_HEADER_LEN > data_end)
        return -1;

    if ((gtpu->flags >> 5) != GTPU_VERSION)
        return -1;

    if ((gtpu->flags & 0x10) != (GTPU_PROTOCOL_TYPE << 4))
        return -1;

    *hdr_len = gtpu_hdrlen(gtpu->flags);

    if (nh->pos + *hdr_len > data_end)
        return -1;

    if (gtpu->flags & GTPU_EXT_HEADER_MASK) {
        struct gtpu_ext_header *ext_hdr = nh->pos + GTPU_HEADER_LEN;
        __u8 ext_len = ext_hdr->ext_len;

        while (ext_len) {
            if (nh->pos + *hdr_len + ext_len * 4 > data_end)
                return -1;

            *hdr_len += ext_len * 4;

            ext_hdr = nh->pos + *hdr_len - 2;
            ext_len = ext_hdr->ext_len;
        }
    }

    nh->pos += *hdr_len;
    *gtpuhdr = gtpu;
    return 0;
}

static __always_inline void update_stats(int packet_type, __u64 bytes)
{
    __u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&upf_stats_map, &key);

    if (!stats)
        return;

    stats->rx_packets++;
    stats->rx_bytes += bytes;

    switch (packet_type) {
        case 0:
            stats->gtpu_packets++;
            stats->teid_hit++;
            stats->tx_packets++;
            stats->tx_bytes += bytes;
            break;
        case 1:
            stats->gtpu_packets++;
            stats->teid_miss++;
            stats->drop_packets++;
            break;
        case 2:
            stats->drop_packets++;
            break;
    }
}

static __always_inline int decap_and_forward(struct xdp_md *ctx,
                                             struct hdr_cursor *nh,
                                             void *data_end,
                                             struct ethhdr *outer_eth,
                                             __u16 gtpu_hdr_len,
                                             struct pdr_value *pdr)
{
    __u32 outer_hdr_len = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr) + gtpu_hdr_len;
    __u32 inner_offset = outer_hdr_len;

    struct ethhdr *inner_eth = (void *)outer_eth + inner_offset;
    if ((void *)(inner_eth + 1) > data_end)
        return -1;

    if (bpf_xdp_adjust_head(ctx, (int)outer_hdr_len))
        return -1;

    void *new_data = (void *)(long)ctx->data;
    void *new_data_end = (void *)(long)ctx->data_end;

    inner_eth = new_data;
    if ((void *)(inner_eth + 1) > new_data_end)
        return -1;

    __builtin_memcpy(inner_eth->h_dest, pdr->dst_mac, ETH_ALEN);

    if (pdr->action == PDR_ACTION_REDIRECT && pdr->ifindex > 0) {
        return bpf_redirect_map(&upf_forward_map, pdr->ifindex, 0);
    }

    return XDP_TX;
}

SEC("xdp")
int upf_xdp_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data, .end = data_end };
    struct ethhdr *outer_eth;
    struct iphdr *outer_ip;
    struct udphdr *udph;
    struct gtpu_header *gtpu;
    __u16 gtpu_hdr_len;
    int eth_type, ip_proto;
    __u64 pkt_len = data_end - data;

    eth_type = parse_ethhdr(&nh, data_end, &outer_eth);
    if (eth_type < 0) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    if (eth_type != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip_proto = parse_iphdr(&nh, data_end, &outer_ip);
    if (ip_proto < 0) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    if (ip_proto != IPPROTO_UDP)
        return XDP_PASS;

    if (parse_udphdr(&nh, data_end, &udph) < 0) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    if (!is_gtpu_packet(udph))
        return XDP_PASS;

    if (parse_gtpuhdr(&nh, data_end, &gtpu, &gtpu_hdr_len) < 0) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    if (gtpu->message_type != 0xFF)
        return XDP_PASS;

    struct pdr_key key = { .teid = gtpu->teid };
    struct pdr_value *pdr = bpf_map_lookup_elem(&teid_pdr_map, &key);

    if (!pdr) {
        update_stats(1, pkt_len);
        return XDP_DROP;
    }

    if (pdr->action == PDR_ACTION_DROP) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    int action = decap_and_forward(ctx, &nh, data_end, outer_eth,
                                   gtpu_hdr_len, pdr);
    if (action < 0) {
        update_stats(2, pkt_len);
        return XDP_DROP;
    }

    update_stats(0, pkt_len);
    return action;
}

SEC("xdp")
int upf_xdp_egress(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
