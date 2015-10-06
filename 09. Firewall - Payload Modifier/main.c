#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>

void tcp_send_check(struct sk_buff *skb) {
	if (skb_is_nonlinear(skb)) {
		skb_linearize(skb);
	}
	struct iphdr *ip_header = ip_hdr(skb);
	struct tcphdr *tcp_header = tcp_hdr(skb);
	unsigned int tcp_header_length = (skb->len - (ip_header->ihl << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(
		tcp_header_length,
		ip_header->saddr,
		ip_header->daddr,
		csum_partial(
			(char*)tcp_header,
			tcp_header_length,
			0
		)
	);
	skb->ip_summed = CHECKSUM_NONE;
}

static unsigned int switch_hook_forward(
	unsigned int hook,
	struct sk_buff *skb,
	const struct net_device *dev_in,
	const struct net_device *dev_out,
	int (*okfn)(struct sk_buff *)
) {
	//   layer 2   //
	//-------------// skb->data
	//   layer 3   //
	unsigned int result = NF_ACCEPT;
	struct ethhdr *eth_header = eth_hdr(skb);
	if (ntohs(eth_header->h_proto) == ETH_P_IP) {
		struct iphdr *ip_header = ip_hdr(skb);
		unsigned int ip_header_length = ip_hdrlen(skb);
		unsigned int ip_packet_length = ntohs(ip_header->tot_len);
		if (ip_header->protocol == IPPROTO_TCP) {
			skb_pull(skb, ip_header_length);
			//   layer 3   //
			//-------------// skb->data
			//   layer 4   //
			skb_reset_transport_header(skb);
			skb_push(skb, ip_header_length);
			//   layer 2   //
			//-------------// skb->data
			//   layer 3   //
			struct tcphdr *tcp_header = tcp_hdr(skb);
			unsigned char *payload = (unsigned char *)ip_header + ip_header_length;
			int i;
			for (i = 0; i < ip_packet_length - ip_header_length - 4; i++) {
				unsigned char byte0 = *(payload + i + 0);
				unsigned char byte1 = *(payload + i + 1);
				unsigned char byte2 = *(payload + i + 2);
				unsigned char byte3 = *(payload + i + 3);
				if (byte0 == 'f' && byte1 == 'u' && byte2 == 'c' && byte3 == 'k') {
					*(payload + i + 0) = '*';
					*(payload + i + 1) = '*';
					*(payload + i + 2) = '*';
					*(payload + i + 3) = '*';
					tcp_send_check(skb);
				}
			}
		}
	}
	//   layer 2   //
	//-------------// skb->data
	//   layer 3   //
	return result;
}

static struct nf_hook_ops switch_hooks[] __read_mostly = {{
	.hook     = switch_hook_forward,
	.owner    = THIS_MODULE,
	.pf       = NFPROTO_BRIDGE,
	.hooknum  = NF_BR_FORWARD,
	.priority = NF_BR_PRI_FILTER_BRIDGED,
}};

static int __init switch_init(void) {
	printk("[switch] init.\n");
	if (nf_register_hooks(
		switch_hooks,
		ARRAY_SIZE(switch_hooks)) < 0
	) {
		printk("[switch] register hooks: failure.\n");
	} else {
		printk("[switch] register hooks: success.\n");
	}
	return 0;
}

static void switch_exit(void) {
	nf_unregister_hooks(
		switch_hooks,
		ARRAY_SIZE(switch_hooks));
	printk("[switch] exit.\n");
}

module_init(switch_init);
module_exit(switch_exit);
