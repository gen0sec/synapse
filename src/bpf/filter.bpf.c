#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "filter.h"

#define NF_DROP         0
#define NF_ACCEPT       1
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define IP_MF           0x2000
#define IP_OFFSET       0x1FFF
#define NEXTHDR_FRAGMENT    44

// TCP fingerprinting constants
#define TCP_FINGERPRINT_MAX_ENTRIES    10000
#define TCP_FP_KEY_SIZE                20  // 4 bytes IP + 2 bytes port + 14 bytes fingerprint
#define TCP_FP_MAX_OPTIONS             10
#define TCP_FP_MAX_OPTION_LEN          40


static inline bool is_frag_v4(const struct iphdr *iph)
{
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}

static inline bool is_frag_v6(const struct ipv6hdr *ip6h)
{
	return ip6h->nexthdr == NEXTHDR_FRAGMENT;
}


struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
};

// TCP fingerprinting structures
struct tcp_fingerprint_key {
    __be32 src_ip;      // Source IP address (IPv4)
    __be16 src_port;    // Source port
    __u8 fingerprint[14]; // TCP fingerprint string (null-terminated)
};

struct tcp_fingerprint_key_v6 {
    __u8 src_ip[16];    // Source IP address (IPv6)
    __be16 src_port;    // Source port
    __u8 fingerprint[14]; // TCP fingerprint string (null-terminated)
};

struct tcp_fingerprint_data {
    __u64 first_seen;   // Timestamp of first packet
    __u64 last_seen;    // Timestamp of last packet
    __u32 packet_count; // Number of packets seen
    __u16 ttl;          // Initial TTL
    __u16 mss;          // Maximum Segment Size
    __u16 window_size;  // TCP window size
    __u8 window_scale; // Window scaling factor
    __u8 options_len;   // Length of TCP options
    __u8 options[TCP_FP_MAX_OPTION_LEN]; // TCP options data
};

struct tcp_syn_stats {
    __u64 total_syns;
    __u64 unique_fingerprints;
    __u64 last_reset;
};

struct src_port_key_v4 {
    __be32 addr;
    __be16 port;
};

struct src_port_key_v6 {
    __u8 addr[16];
    __be16 port;
};

// IPv4 maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);           // IPv4 address in network byte order
	__type(value, ip_flag_t);     // presence flag (1)
} banned_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, ip_flag_t);
} recently_banned_ips SEC(".maps");

// IPv6 maps: permanently banned and recently banned
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, ip_flag_t);
} banned_ips_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, CITADEL_IP_MAP_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, ip_flag_t);
} recently_banned_ips_v6 SEC(".maps");

// Remove dynptr helpers, not used in XDP manual parsing
// extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
//                   struct bpf_dynptr *ptr__uninit) __ksym;
// extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
//                   void *buffer, uint32_t buffer__sz) __ksym;

volatile int shootdowns = 0;

// Statistics maps for tracking access rule hits
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ipv4_banned_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ipv4_recently_banned_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ipv6_banned_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ipv6_recently_banned_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_packets_processed SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} total_packets_dropped SEC(".maps");

// TCP fingerprinting maps
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
	__type(key, struct tcp_fingerprint_key);
	__type(value, struct tcp_fingerprint_data);
} tcp_fingerprints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
	__type(key, struct tcp_fingerprint_key_v6);
	__type(value, struct tcp_fingerprint_data);
} tcp_fingerprints_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tcp_syn_stats);
} tcp_syn_stats SEC(".maps");

// Blocked TCP fingerprint maps (only store the fingerprint string, not per-IP)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);  // Store up to 10k blocked fingerprint patterns
	__type(key, __u8[14]);        // TCP fingerprint string (14 bytes)
	__type(value, __u8);          // Flag (1 = blocked)
} blocked_tcp_fingerprints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u8[14]);        // TCP fingerprint string (14 bytes)
	__type(value, __u8);          // Flag (1 = blocked)
} blocked_tcp_fingerprints_v6 SEC(".maps");

// Statistics for TCP fingerprint blocks
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tcp_fingerprint_blocks_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tcp_fingerprint_blocks_ipv6 SEC(".maps");

// Maps to track dropped IP addresses with counters
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);  // Track up to 1000 unique dropped IPs
    __type(key, __be32);         // IPv4 address
    __type(value, __u64);        // Drop count
} dropped_ipv4_addresses SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);  // Track up to 1000 unique dropped IPv6s
    __type(key, __u8[16]);      // IPv6 address
    __type(value, __u64);        // Drop count
} dropped_ipv6_addresses SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct src_port_key_v4);
    __type(value, __u8);
} banned_inbound_ipv4_address_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct src_port_key_v6);
    __type(value, __u8);
} banned_inbound_ipv6_address_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct src_port_key_v4);
    __type(value, __u8);
} banned_outbound_ipv4_address_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct src_port_key_v6);
    __type(value, __u8);
} banned_outbound_ipv6_address_ports SEC(".maps");

/*
 * Helper for bounds checking and advancing a cursor.
 *
 * @cursor: pointer to current parsing position
 * @end:    pointer to end of packet data
 * @len:    length of the struct to read
 *
 * Returns a pointer to the struct if it's within bounds,
 * and advances the cursor. Returns NULL otherwise.
 */
static void *parse_and_advance(void **cursor, void *end, __u32 len)
{
    void *current = *cursor;
    if (current + len > end)
        return NULL;
    *cursor = current + len;
    return current;
}

/*
 * Helper functions for incrementing statistics counters
 */
static void increment_ipv4_banned_stats(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ipv4_banned_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_ipv4_recently_banned_stats(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ipv4_recently_banned_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_ipv6_banned_stats(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ipv6_banned_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_ipv6_recently_banned_stats(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ipv6_recently_banned_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_total_packets_processed(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&total_packets_processed, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_total_packets_dropped(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&total_packets_dropped, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_dropped_ipv4_address(__be32 ip_addr)
{
    __u64 *value = bpf_map_lookup_elem(&dropped_ipv4_addresses, &ip_addr);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        // First time dropping this IP, initialize counter
        __u64 initial_count = 1;
        bpf_map_update_elem(&dropped_ipv4_addresses, &ip_addr, &initial_count, BPF_ANY);
    }
}

static void increment_dropped_ipv6_address(struct in6_addr ip_addr)
{
    __u8 *addr_bytes = (__u8 *)&ip_addr;
    __u64 *value = bpf_map_lookup_elem(&dropped_ipv6_addresses, addr_bytes);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        // First time dropping this IP, initialize counter
        __u64 initial_count = 1;
        bpf_map_update_elem(&dropped_ipv6_addresses, addr_bytes, &initial_count, BPF_ANY);
    }
}

/*
 * TCP fingerprinting helper functions
 */
static void increment_tcp_syn_stats(void)
{
    __u32 key = 0;
    struct tcp_syn_stats *stats = bpf_map_lookup_elem(&tcp_syn_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_syns, 1);
    } else {
        struct tcp_syn_stats new_stats = {0};
        new_stats.total_syns = 1;
        bpf_map_update_elem(&tcp_syn_stats, &key, &new_stats, BPF_ANY);
    }
}

static void increment_unique_fingerprints(void)
{
    __u32 key = 0;
    struct tcp_syn_stats *stats = bpf_map_lookup_elem(&tcp_syn_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->unique_fingerprints, 1);
    }
}

static void increment_tcp_fingerprint_blocks_ipv4(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&tcp_fingerprint_blocks_ipv4, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static void increment_tcp_fingerprint_blocks_ipv6(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&tcp_fingerprint_blocks_ipv6, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static int parse_tcp_mss_wscale(struct tcphdr *tcp, void *data_end, __u16 *mss_out, __u8 *wscale_out)
{
    __u8 *ptr = (__u8 *)tcp + sizeof(struct tcphdr);
    __u32 options_len = (tcp->doff * 4) - sizeof(struct tcphdr);
    __u8 *end = ptr + options_len;

    // Ensure we don't exceed packet bounds
    if (end > (__u8 *)data_end) {
        end = (__u8 *)data_end;
    }

    // Safety check
    if (ptr >= end || ptr >= (__u8 *)data_end) {
        return 0;
    }

    // Parse options - limit to 20 iterations to handle NOPs
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (ptr >= end || ptr >= (__u8 *)data_end) break;
        if (ptr + 1 > (__u8 *)data_end) break;

        __u8 kind = *ptr;
        if (kind == 0) break; // End of options

        if (kind == 1) {
            // NOP option
            ptr++;
            continue;
        }

        // Check bounds for option length
        if (ptr + 2 > (__u8 *)data_end) break;
        __u8 len = *(ptr + 1);
        if (len < 2 || ptr + len > (__u8 *)data_end) break;

        // MSS option (kind=2, len=4)
        if (kind == 2 && len == 4 && ptr + 4 <= (__u8 *)data_end) {
            *mss_out = (*(ptr + 2) << 8) | *(ptr + 3);
        }
        // Window scale option (kind=3, len=3)
        else if (kind == 3 && len == 3 && ptr + 3 <= (__u8 *)data_end) {
            *wscale_out = *(ptr + 2);
        }

        ptr += len;
    }

    return 0;
}

static void generate_tcp_fingerprint(struct tcphdr *tcp, void *data_end, __u16 ttl, __u8 *fingerprint)
{
    // Generate JA4T-style fingerprint: ttl:mss:window:scale
    __u16 mss = 0;
    __u8 window_scale = 0;

    // Parse TCP options to extract MSS and window scaling
    parse_tcp_mss_wscale(tcp, data_end, &mss, &window_scale);

    // Generate fingerprint string manually (BPF doesn't support complex formatting)
    __u16 window = bpf_ntohs(tcp->window);

    // Format: "ttl:mss:window:scale" (max 14 chars)
    fingerprint[0] = '0' + (ttl / 100);
    fingerprint[1] = '0' + ((ttl / 10) % 10);
    fingerprint[2] = '0' + (ttl % 10);
    fingerprint[3] = ':';
    fingerprint[4] = '0' + (mss / 1000);
    fingerprint[5] = '0' + ((mss / 100) % 10);
    fingerprint[6] = '0' + ((mss / 10) % 10);
    fingerprint[7] = '0' + (mss % 10);
    fingerprint[8] = ':';
    fingerprint[9] = '0' + (window / 10000);
    fingerprint[10] = '0' + ((window / 1000) % 10);
    fingerprint[11] = '0' + ((window / 100) % 10);
    fingerprint[12] = '0' + ((window / 10) % 10);
    fingerprint[13] = '0' + (window % 10);
    // Note: window_scale is not included due to space constraints
}

/*
 * Check if a TCP fingerprint is blocked (IPv4)
 * Returns true if the fingerprint should be blocked
 */
static bool is_tcp_fingerprint_blocked(__u8 *fingerprint)
{
    __u8 *blocked = bpf_map_lookup_elem(&blocked_tcp_fingerprints, fingerprint);
    return (blocked != NULL && *blocked == 1);
}

/*
 * Check if a TCP fingerprint is blocked (IPv6)
 * Returns true if the fingerprint should be blocked
 */
static bool is_tcp_fingerprint_blocked_v6(__u8 *fingerprint)
{
    __u8 *blocked = bpf_map_lookup_elem(&blocked_tcp_fingerprints_v6, fingerprint);
    return (blocked != NULL && *blocked == 1);
}

static void record_tcp_fingerprint(__be32 src_ip, __be16 src_port,
                                struct tcphdr *tcp, void *data_end, __u16 ttl)
{
    // Skip localhost traffic to reduce noise
    // Check for 127.0.0.0/8 range (127.0.0.1 to 127.255.255.255)
    if ((src_ip & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000)) {
        return;
    }

    struct tcp_fingerprint_key key = {0};
    struct tcp_fingerprint_data data = {0};
    __u64 timestamp = bpf_ktime_get_ns();

    key.src_ip = src_ip;
    key.src_port = src_port;

    // Generate fingerprint
    generate_tcp_fingerprint(tcp, data_end, ttl, key.fingerprint);

    // Check if fingerprint already exists
    struct tcp_fingerprint_data *existing = bpf_map_lookup_elem(&tcp_fingerprints, &key);
    if (existing) {
        // Update existing entry - must copy to local variable first
        data.first_seen = existing->first_seen;
        data.last_seen = timestamp;
        data.packet_count = existing->packet_count + 1;
        data.ttl = existing->ttl;
        data.mss = existing->mss;
        data.window_size = existing->window_size;
        data.window_scale = existing->window_scale;
        data.options_len = existing->options_len;

        // Copy options array
        #pragma unroll
        for (int i = 0; i < TCP_FP_MAX_OPTION_LEN; i++) {
            data.options[i] = existing->options[i];
        }

        bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
    } else {
        // Create new entry
        data.first_seen = timestamp;
        data.last_seen = timestamp;
        data.packet_count = 1;
        data.ttl = ttl;
        data.window_size = bpf_ntohs(tcp->window);

        // Extract MSS and window scale from options
        parse_tcp_mss_wscale(tcp, data_end, &data.mss, &data.window_scale);

        bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
        increment_unique_fingerprints();

        // Log new TCP fingerprint
        //bpf_printk("TCP_FP: New fingerprint from %pI4:%d - TTL:%d MSS:%d WS:%d Window:%d",
        //           &src_ip, bpf_ntohs(src_port), ttl, data.mss, data.window_scale, data.window_size);
    }
}

SEC("xdp")
int arxignis_xdp_filter(struct xdp_md *ctx)
{
    // This filter is designed to only block incoming traffic
    // It should be attached only to ingress hooks, not egress
    // The filtering logic below blocks packets based on source IP addresses
    //
    // IP Version Support:
    // - Supports IPv4-only, IPv6-only, and hybrid (both) modes
    // - Note: XDP requires IPv6 to be enabled at kernel level for attachment,
    //   even when processing only IPv4 packets. This is a kernel limitation.
    // - The BPF program processes both IPv4 and IPv6 packets based on the
    //   ethernet protocol type (ETH_P_IP for IPv4, ETH_P_IPV6 for IPv6)

    void *data_end = (void *)(long)ctx->data_end;
    void *cursor = (void *)(long)ctx->data;

    // Debug: Count all packets
    __u32 zero = 0;
    __u32 *packet_count = bpf_map_lookup_elem(&total_packets_processed, &zero);
    if (packet_count) {
        __sync_fetch_and_add(packet_count, 1);
    }

    struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
    if (!eth)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    // Increment total packets processed counter
    increment_total_packets_processed();

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
        if (!iph)
            return XDP_PASS;

        struct lpm_key key = {
            .prefixlen = 32,
            .addr = iph->saddr,
        };

        if (bpf_map_lookup_elem(&banned_ips, &key)) {
            increment_ipv4_banned_stats();
            increment_total_packets_dropped();
            increment_dropped_ipv4_address(iph->saddr);
            //bpf_printk("XDP: BLOCKED incoming permanently banned IPv4 %pI4", &iph->saddr);
            return XDP_DROP;
        }

        if (bpf_map_lookup_elem(&recently_banned_ips, &key)) {
            increment_ipv4_recently_banned_stats();
            // Block UDP and ICMP from recently banned IPs, but allow DNS
            if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
                if (udph && udph->dest == bpf_htons(53)) {
                    return XDP_PASS; // Allow DNS responses
                }
                // Block other UDP traffic
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips, &key);
                increment_total_packets_dropped();
                increment_dropped_ipv4_address(iph->saddr);
                //bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                return XDP_DROP;
            }
            if (iph->protocol == IPPROTO_ICMP) {
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips, &key);
                increment_total_packets_dropped();
                increment_dropped_ipv4_address(iph->saddr);
                //bpf_printk("XDP: BLOCKED incoming ICMP from recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                return XDP_DROP;
            }
            // For TCP, only promote to banned on FIN/RST
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
                if (tcph) {
                    // Perform TCP fingerprinting ONLY on SYN packets (not SYN-ACK)
                    // This ensures we capture the initial handshake with MSS/WSCALE
                    if (tcph->syn && !tcph->ack) {
                        increment_tcp_syn_stats();
                        
                        // Generate fingerprint to check if blocked
                        __u8 fingerprint[14] = {0};
                        generate_tcp_fingerprint(tcph, data_end, iph->ttl, fingerprint);
                        
                        // Check if this TCP fingerprint is blocked
                        if (is_tcp_fingerprint_blocked(fingerprint)) {
                            increment_tcp_fingerprint_blocks_ipv4();
                            increment_total_packets_dropped();
                            increment_dropped_ipv4_address(iph->saddr);
                            return XDP_DROP;
                        }
                        
                        record_tcp_fingerprint(iph->saddr, tcph->source, tcph, data_end, iph->ttl);
                    }

                    if (tcph->fin || tcph->rst) {
                        ip_flag_t one = 1;
                        bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
                        bpf_map_delete_elem(&recently_banned_ips, &key);
                        increment_total_packets_dropped();
                        increment_dropped_ipv4_address(iph->saddr);
                        //bpf_printk("XDP: TCP FIN/RST from incoming recently banned IPv4 %pI4, promoted to permanent ban", &iph->saddr);
                    }
                }
            }
            return XDP_PASS;
        }

        // Perform TCP fingerprinting ONLY on SYN packets
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
            if (tcph) {
                // Only fingerprint SYN packets (not SYN-ACK) to capture MSS/WSCALE
                if (tcph->syn && !tcph->ack) {
                    increment_tcp_syn_stats();
                    
                    // Generate fingerprint to check if blocked
                    __u8 fingerprint[14] = {0};
                    generate_tcp_fingerprint(tcph, data_end, iph->ttl, fingerprint);
                    
                    // Check if this TCP fingerprint is blocked
                    if (is_tcp_fingerprint_blocked(fingerprint)) {
                        increment_tcp_fingerprint_blocks_ipv4();
                        increment_total_packets_dropped();
                        increment_dropped_ipv4_address(iph->saddr);
                        //bpf_printk("XDP: BLOCKED TCP fingerprint from IPv4 %pI4:%d - FP:%s",
                        //           &iph->saddr, bpf_ntohs(tcph->source), fingerprint);
                        return XDP_DROP;
                    }
                    
                    // Record fingerprint for monitoring
                    record_tcp_fingerprint(iph->saddr, tcph->source, tcph, data_end, iph->ttl);
                }
            }
        }

        // Check IPv4 port bans
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            void *port_cursor = cursor;
            __be16 src_port = 0;
            __be16 dst_port = 0;

            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph_tmp = parse_and_advance(&port_cursor, data_end, sizeof(*tcph_tmp));
                if (!tcph_tmp)
                    return XDP_PASS;
                src_port = tcph_tmp->source;
                dst_port = tcph_tmp->dest;
            } else {
                struct udphdr *udph_tmp = parse_and_advance(&port_cursor, data_end, sizeof(*udph_tmp));
                if (!udph_tmp)
                    return XDP_PASS;
                src_port = udph_tmp->source;
                dst_port = udph_tmp->dest;
            }

            struct src_port_key_v4 inbound_key = {
                .addr = iph->saddr,
                .port = src_port,
            };

            if (bpf_map_lookup_elem(&banned_inbound_ipv4_address_ports, &inbound_key)) {
                increment_total_packets_dropped();
                increment_dropped_ipv4_address(iph->saddr);
                return XDP_DROP;
            }

            struct src_port_key_v4 outbound_key = {
                .addr = iph->daddr,
                .port = dst_port,
            };

            if (bpf_map_lookup_elem(&banned_outbound_ipv4_address_ports, &outbound_key)) {
                increment_total_packets_dropped();
                increment_dropped_ipv4_address(iph->daddr);
                return XDP_DROP;
            }
        }

        return XDP_PASS;
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = parse_and_advance(&cursor, data_end, sizeof(*ip6h));
        if (!ip6h)
            return XDP_PASS;

        // Always allow DNS traffic (UDP port 53) to pass through
        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
            if (udph && (udph->dest == bpf_htons(53) || udph->source == bpf_htons(53))) {
                return XDP_PASS; // Always allow DNS traffic
            }
        }

        // Check banned/recently banned maps by source IPv6
        struct lpm_key_v6 key6 = {
            .prefixlen = 128,
        };
        // Manual copy for BPF compatibility
        __u8 *src_addr = (__u8 *)&ip6h->saddr;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            key6.addr[i] = src_addr[i];
        }

        if (bpf_map_lookup_elem(&banned_ips_v6, &key6)) {
            increment_ipv6_banned_stats();
            increment_total_packets_dropped();
            increment_dropped_ipv6_address(ip6h->saddr);
            //bpf_printk("XDP: BLOCKED incoming permanently banned IPv6");
            return XDP_DROP;
        }

        if (bpf_map_lookup_elem(&recently_banned_ips_v6, &key6)) {
            increment_ipv6_recently_banned_stats();
            // Block UDP and ICMP from recently banned IPv6 IPs, but allow DNS
            if (ip6h->nexthdr == IPPROTO_UDP) {
                struct udphdr *udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
                if (udph && udph->dest == bpf_htons(53)) {
                    return XDP_PASS; // Allow DNS responses
                }
                // Block other UDP traffic
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                increment_total_packets_dropped();
                increment_dropped_ipv6_address(ip6h->saddr);
                //bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv6, promoted to permanent ban");
                return XDP_DROP;
            }
            if (ip6h->nexthdr == 58) { // 58 = IPPROTO_ICMPV6
                ip_flag_t one = 1;
                bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                increment_total_packets_dropped();
                increment_dropped_ipv6_address(ip6h->saddr);
                //bpf_printk("XDP: BLOCKED incoming ICMPv6 from recently banned IPv6, promoted to permanent ban");
                return XDP_DROP;
            }
            // For TCP, only promote to banned on FIN/RST
            if (ip6h->nexthdr == IPPROTO_TCP) {
                struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
                if (tcph) {
                    if (tcph->fin || tcph->rst) {
                        ip_flag_t one = 1;
                        bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
                        bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
                        increment_total_packets_dropped();
                        increment_dropped_ipv6_address(ip6h->saddr);
                        //bpf_printk("XDP: TCP FIN/RST from incoming recently banned IPv6, promoted to permanent ban");
                    }
                }
            }
            return XDP_PASS; // Allow if recently banned
        }

        // Perform TCP fingerprinting on IPv6 TCP packets
        if (ip6h->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
            if (tcph) {
                // Perform TCP fingerprinting ONLY on SYN packets (not SYN-ACK)
                // This ensures we capture the initial handshake with MSS/WSCALE
                if (tcph->syn && !tcph->ack) {
                    // Skip IPv6 localhost traffic to reduce noise
                    // Check for ::1 (IPv6 localhost) - manual comparison
                    __u8 *src_addr = (__u8 *)&ip6h->saddr;
                    bool is_localhost = true;
                    
                    // Check first 15 bytes are zero
                    #pragma unroll
                    for (int i = 0; i < 15; i++) {
                        if (src_addr[i] != 0) {
                            is_localhost = false;
                            break;
                        }
                    }
                    // Check last byte is 1
                    if (is_localhost && src_addr[15] == 1) {
                        return XDP_PASS;
                    }

                    // Extract TTL from IPv6 hop limit
                    __u16 ttl = ip6h->hop_limit;

                    // Generate fingerprint to check if blocked
                    __u8 fingerprint[14] = {0};
                    generate_tcp_fingerprint(tcph, data_end, ttl, fingerprint);
                    
                    // Check if this TCP fingerprint is blocked
                    if (is_tcp_fingerprint_blocked_v6(fingerprint)) {
                        increment_tcp_fingerprint_blocks_ipv6();
                        increment_total_packets_dropped();
                        increment_dropped_ipv6_address(ip6h->saddr);
                        //bpf_printk("XDP: BLOCKED TCP fingerprint from IPv6 %pI6:%d - FP:%s",
                        //           &ip6h->saddr, bpf_ntohs(tcph->source), fingerprint);
                        return XDP_DROP;
                    }

                    // Create IPv6 fingerprint key with full 128-bit address
                    struct tcp_fingerprint_key_v6 key = {0};
                    struct tcp_fingerprint_data data = {0};
                    __u64 timestamp = bpf_ktime_get_ns();

                    // Copy full IPv6 address (16 bytes) - manual copy for BPF
                    #pragma unroll
                    for (int i = 0; i < 16; i++) {
                        key.src_ip[i] = src_addr[i];
                    }
                    key.src_port = tcph->source;

                    // Copy fingerprint to key
                    #pragma unroll
                    for (int i = 0; i < 14; i++) {
                        key.fingerprint[i] = fingerprint[i];
                    }

                    // Check if fingerprint already exists in IPv6 map
                    struct tcp_fingerprint_data *existing = bpf_map_lookup_elem(&tcp_fingerprints_v6, &key);
                    if (existing) {
                        // Update existing entry - must copy to local variable first
                        data.first_seen = existing->first_seen;
                        data.last_seen = timestamp;
                        data.packet_count = existing->packet_count + 1;
                        data.ttl = existing->ttl;
                        data.mss = existing->mss;
                        data.window_size = existing->window_size;
                        data.window_scale = existing->window_scale;
                        data.options_len = existing->options_len;

                        // Copy options array
                        #pragma unroll
                        for (int i = 0; i < TCP_FP_MAX_OPTION_LEN; i++) {
                            data.options[i] = existing->options[i];
                        }

                        bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
                    } else {
                        // Create new entry
                        data.first_seen = timestamp;
                        data.last_seen = timestamp;
                        data.packet_count = 1;
                        data.ttl = ttl;
                        data.window_size = bpf_ntohs(tcph->window);

                        // Extract MSS and window scale from options
                        parse_tcp_mss_wscale(tcph, data_end, &data.mss, &data.window_scale);

                        bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
                        increment_unique_fingerprints();

                        // Log new IPv6 TCP fingerprint
                        //bpf_printk("TCP_FP: New IPv6 fingerprint from %pI6:%d - TTL:%d MSS:%d WS:%d Window:%d",
                        //           &ip6h->saddr, bpf_ntohs(tcph->source), ttl, data.mss, data.window_scale, data.window_size);
                    }
                }
            }
        }

        // Check IPv6 port bans
        if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
            void *port_cursor = cursor;
            __be16 src_port = 0;
            __be16 dst_port = 0;

            if (ip6h->nexthdr == IPPROTO_TCP) {
                struct tcphdr *tcph_tmp = parse_and_advance(&port_cursor, data_end, sizeof(*tcph_tmp));
                if (!tcph_tmp)
                    return XDP_PASS;
                src_port = tcph_tmp->source;
                dst_port = tcph_tmp->dest;
            } else {
                struct udphdr *udph_tmp = parse_and_advance(&port_cursor, data_end, sizeof(*udph_tmp));
                if (!udph_tmp)
                    return XDP_PASS;
                src_port = udph_tmp->source;
                dst_port = udph_tmp->dest;
            }

            struct src_port_key_v6 inbound_key6 = {0};
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                inbound_key6.addr[i] = ((__u8 *)&ip6h->saddr)[i];
            }
            inbound_key6.port = src_port;

            if (bpf_map_lookup_elem(&banned_inbound_ipv6_address_ports, &inbound_key6)) {
                increment_total_packets_dropped();
                increment_dropped_ipv6_address(ip6h->saddr);
                return XDP_DROP;
            }

            struct src_port_key_v6 outbound_key6 = {0};
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                outbound_key6.addr[i] = ((__u8 *)&ip6h->daddr)[i];
            }
            outbound_key6.port = dst_port;

            if (bpf_map_lookup_elem(&banned_outbound_ipv6_address_ports, &outbound_key6)) {
                increment_total_packets_dropped();
                increment_dropped_ipv6_address(ip6h->daddr);
                return XDP_DROP;
            }
        }

        return XDP_PASS;
    }

    return XDP_PASS;
    // return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
