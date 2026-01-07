#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>

#if IS_ENABLED(CONFIG_IPV6) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <net/transp_v6.h>
#else
#warning IPv6 support is disabled. TCP-Brutal-300mbps will only work with IPv4. \
 Please ensure you have enabled CONFIG_IPV6 in your kernel config \
 and your kernel version is greater than 5.8.
#endif

#define INIT_PACING_RATE 37500000 // 37,500,000 Bytes/s = 300 Mbps 
#define INIT_CWND_GAIN 30

#define MIN_PACING_RATE 62500 // 500 Kbps
#define MIN_CWND_GAIN 5
#define MAX_CWND_GAIN 80
#define MIN_CWND 4

#ifndef ICSK_CA_PRIV_SIZE
#error "ICSK_CA_PRIV_SIZE not defined"
#else
// This is the size of the private data area in struct inet_connection_sock
// The size varies between Linux versions
// We use it to calculate the number of slots in the packet info array
#define RAW_PKT_INFO_SLOTS ((ICSK_CA_PRIV_SIZE - 2 * sizeof(u64)) / sizeof(struct tcp_brutal_300mbps_pkt_info))
#define PKT_INFO_SLOTS (RAW_PKT_INFO_SLOTS < 3 ? 3 : (RAW_PKT_INFO_SLOTS > 5 ? 5 : RAW_PKT_INFO_SLOTS))
#endif

#define MIN_PKT_INFO_SAMPLES 50
#define MIN_ACK_RATE_PERCENT 80

#define TCP_BRUTAL_300MBPS_PARAMS 23301

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(tp->tcp_mstamp, USEC_PER_SEC);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
// see https://github.com/torvalds/linux/commit/9a568de4818dea9a05af141046bd3e589245ab83
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(tp->tcp_mstamp.stamp_us, USEC_PER_SEC);
}
#else
#include <linux/jiffies.h>
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(jiffies_to_usecs(tcp_time_stamp), USEC_PER_SEC);
}
#endif

struct tcp_brutal_300mbps_pkt_info
{
    u64 sec;
    u32 acked;
    u32 losses;
};

struct tcp_brutal_300mbps
{
    u64 rate;
    u32 cwnd_gain;

    struct tcp_brutal_300mbps_pkt_info slots[PKT_INFO_SLOTS];
};

struct tcp_brutal_300mbps_params
{
    u64 rate;      
    u32 cwnd_gain; 
} __packed;

static struct proto tcp_prot_override_300mbps __ro_after_init;
#ifdef _TRANSP_V6_H
static struct proto tcpv6_prot_override_300mbps __ro_after_init;
#endif 

#ifdef _LINUX_SOCKPTR_H
static int tcp_brutal_300mbps_set_params(struct sock *sk, sockptr_t optval, unsigned int optlen)
#else
static int tcp_brutal_300mbps_set_params(struct sock *sk, char __user *optval, unsigned int optlen)
#endif
{
    struct tcp_brutal_300mbps *ca = inet_csk_ca(sk);
    struct tcp_brutal_300mbps_params params;

    if (optlen < sizeof(params))
        return -EINVAL;

#ifdef _LINUX_SOCKPTR_H
    if (copy_from_sockptr(&params, optval, sizeof(params)))
        return -EFAULT;
#else
    if (copy_from_user(&params, optval, sizeof(params)))
        return -EFAULT;
#endif

    // Sanity checks
    if (params.rate < MIN_PACING_RATE)
        return -EINVAL;
    if (params.cwnd_gain < MIN_CWND_GAIN || params.cwnd_gain > MAX_CWND_GAIN)
        return -EINVAL;

    ca->rate = params.rate;
    ca->cwnd_gain = params.cwnd_gain;

    return 0;
}

#ifdef _LINUX_SOCKPTR_H
static int tcp_brutal_300mbps_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
#else
static int tcp_brutal_300mbps_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen)
#endif
{
    if (level == IPPROTO_TCP && optname == TCP_BRUTAL_300MBPS_PARAMS)
        return tcp_brutal_300mbps_set_params(sk, optval, optlen);
    else
        return tcp_prot.setsockopt(sk, level, optname, optval, optlen);
}

#ifdef _TRANSP_V6_H
#ifdef _LINUX_SOCKPTR_H
static int tcp_brutal_300mbps_v6_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
#else  
static int tcp_brutal_300mbps_v6_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen)
#endif 
{
    if (level == IPPROTO_TCP && optname == TCP_BRUTAL_300MBPS_PARAMS)
        return tcp_brutal_300mbps_set_params(sk, optval, optlen);
    else
        return tcpv6_prot.setsockopt(sk, level, optname, optval, optlen);
}
#endif 

static void tcp_brutal_300mbps_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_brutal_300mbps *ca = inet_csk_ca(sk);

    if (sk->sk_family == AF_INET)
        sk->sk_prot = &tcp_prot_override_300mbps;
#ifdef _TRANSP_V6_H
    else if (sk->sk_family == AF_INET6)
        sk->sk_prot = &tcpv6_prot_override_300mbps;
#endif 
    else
        BUG(); 

    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

    ca->rate = INIT_PACING_RATE;
    ca->cwnd_gain = INIT_CWND_GAIN;

    memset(ca->slots, 0, sizeof(ca->slots));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    // Pacing is REQUIRED for Brutal to work, but Linux only has internal pacing after 4.13.
    // For kernels prior to 4.13, you MUST add fq pacing manually (e.g. "tc qdisc add dev eth0 root fq pacing")
    // or rate control will be broken.
    // See https://github.com/torvalds/linux/commit/218af599fa635b107cfe10acf3249c4dfe5e4123 for details.
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif
}

// Copied from tcp.h for compatibility reasons
static inline u32 tcp_brutal_300mbps_snd_cwnd(const struct tcp_sock *tp)
{
    return tp->snd_cwnd;
}

// Copied from tcp.h for compatibility reasons
static inline void tcp_brutal_300mbps_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
    WARN_ON_ONCE((int)val <= 0);
    tp->snd_cwnd = val;
}

static void tcp_brutal_300mbps_update_rate(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_brutal_300mbps *ca = inet_csk_ca(sk);

    u64 sec = tcp_sock_get_sec(tp);
    u64 min_sec = sec - PKT_INFO_SLOTS;
    u32 acked = 0, losses = 0;
    u32 ack_rate; 
    u64 rate = ca->rate;
    u32 cwnd;

    u32 mss = tp->mss_cache;
    u32 rtt_ms = (tp->srtt_us >> 3) / USEC_PER_MSEC;
    if (!rtt_ms)
        rtt_ms = 1;

    for (int i = 0; i < PKT_INFO_SLOTS; i++)
    {
        if (ca->slots[i].sec >= min_sec)
        {
            acked += ca->slots[i].acked;
            losses += ca->slots[i].losses;
        }
    }
    if (acked + losses < MIN_PKT_INFO_SAMPLES)
        ack_rate = 100;
    else
    {
        ack_rate = acked * 100 / (acked + losses);
        if (ack_rate < MIN_ACK_RATE_PERCENT)
            ack_rate = MIN_ACK_RATE_PERCENT;
    }

    rate *= 100;
    rate = div_u64(rate, ack_rate);

    // The order here is chosen carefully to avoid overflow as much as possible
    cwnd = div_u64(rate, MSEC_PER_SEC);
    cwnd *= rtt_ms;
    cwnd /= mss;
    cwnd *= ca->cwnd_gain;
    cwnd /= 10;
    cwnd = max_t(u32, cwnd, MIN_CWND);

    tcp_brutal_300mbps_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));

    WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate)));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
static void tcp_brutal_300mbps_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
#else
static void tcp_brutal_300mbps_main(struct sock *sk, const struct rate_sample *rs)
#endif
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_brutal_300mbps *ca = inet_csk_ca(sk);

    u64 sec;
    u32 slot;

    // Ignore invalid rate samples
    if (rs->delivered < 0 || rs->interval_us <= 0)
        return;

    sec = tcp_sock_get_sec(tp);
    div_u64_rem(sec, PKT_INFO_SLOTS, &slot);

    if (ca->slots[slot].sec == sec)
    {
        // Current slot, update
        ca->slots[slot].acked += rs->acked_sacked;
        ca->slots[slot].losses += rs->losses;
    }
    else
    {
        // Uninitialized slot or slot expired
        ca->slots[slot].sec = sec;
        ca->slots[slot].acked = rs->acked_sacked;
        ca->slots[slot].losses = rs->losses;
    }

    tcp_brutal_300mbps_update_rate(sk);
}

static u32 tcp_brutal_300mbps_undo_cwnd(struct sock *sk)
{
    return tcp_brutal_300mbps_snd_cwnd(tcp_sk(sk));
}

static u32 tcp_brutal_300mbps_ssthresh(struct sock *sk)
{
    return tcp_sk(sk)->snd_ssthresh;
}

static struct tcp_congestion_ops tcp_brutal_300mbps_ops = {
    .flags = TCP_CONG_NON_RESTRICTED,
    .name = "tcp-brutal-300mbps", // 内核识别名称 
    .owner = THIS_MODULE,
    .init = tcp_brutal_300mbps_init,
    .cong_control = tcp_brutal_300mbps_main,
    .undo_cwnd = tcp_brutal_300mbps_undo_cwnd,
    .ssthresh = tcp_brutal_300mbps_ssthresh,
};

static int __init tcp_brutal_300mbps_register(void)
{
    BUILD_BUG_ON(sizeof(struct tcp_brutal_300mbps) > ICSK_CA_PRIV_SIZE);
    BUILD_BUG_ON(PKT_INFO_SLOTS < 1);

    tcp_prot_override_300mbps = tcp_prot;
    tcp_prot_override_300mbps.setsockopt = tcp_brutal_300mbps_setsockopt;

#ifdef _TRANSP_V6_H
    tcpv6_prot_override_300mbps = tcpv6_prot;
    tcpv6_prot_override_300mbps.setsockopt = tcp_brutal_300mbps_v6_setsockopt;
#endif 

    return tcp_register_congestion_control(&tcp_brutal_300mbps_ops);
}

static void __exit tcp_brutal_300mbps_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_brutal_300mbps_ops);
}

module_init(tcp_brutal_300mbps_register);
module_exit(tcp_brutal_300mbps_unregister);

MODULE_AUTHOR("Aperture Internet Laboratory");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Brutal 300mbps");
MODULE_VERSION("1.0.2");
