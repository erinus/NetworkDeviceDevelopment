#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>

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
	switch (ntohs(eth_header->h_proto)) {
		case ETH_P_IP:
			struct iphdr *ip_header = ip_hdr(skb);
			switch (ntohs(ip_header->protocol)) {
				case IPPROTO_ICMP:	// ICMP (PING)
					break;
				case IPPROTO_TCP:	// TCP
					break;
				case IPPROTO_UDP:	// UDP
					break;
				case IPPROTO_ESP:	// IPSec
					break;
				case IPPROTO_AH:	// IPSec
					break;
			}
			break;
		case ETH_P_ARP:				// ARP
			break;
		case ETH_P_PPP_SES:			// PPPoE
			break;
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
