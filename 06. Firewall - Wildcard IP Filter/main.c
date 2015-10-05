#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>

unsigned int inet_addr(char *str) {
	int a, b, c, d;
	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;
	return *(unsigned int*)arr;
}

unsigned int rule_scan(unsigned int addr, char *rule) {
	unsigned int result = 1;
	int a, b, c, d;
	char data[16];
	int i, offset;
	memset(data, 0, 16);
	sprintf(
		data, "%d.%d.%d.%d",
		(addr >> 0) & 0xFF, (addr >> 8) & 0xFF,
		(addr >> 16) & 0xFF, (addr >> 24) & 0xFF
	);
	offset = 0;
	for (i = 0; i < strlen(rule); i++)
	{
		if (rule[i] == '\0' || data[i + offset] == '\0') {
			break;
		}
		if (rule[i] != data[i + offset]) {
			if (rule[i] == '*' &&
				data[i + offset] >= '0' &&
				data[i + offset] <= '9'
			) {
				i--;
				offset++;
				continue;
			}
			if (rule[i] == '*' && data[i + offset] == '.' ) {
				i++;
				continue;
			}
			result = 0;
			break;
		}
	}
	return result;
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
	if (eth_header->h_proto == 0x0008) {
		struct iphdr *ip_header = ip_hdr(skb);
		if (ip_header->protocol == IPPROTO_TCP) {
			char *rule = "192.168.103.*";
			if (rule_scan(ip_header->saddr, rule) ||
				rule_scan(ip_header->daddr, rule)
			) {
				result = NF_DROP;
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
