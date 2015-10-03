#include <linux/module.h>

static int __init switch_init(void) {
	printk("[switch] hello world\n");
	return 0;
}

static void switch_exit(void) {
	printk("[switch] leave world\n");
}

module_init(switch_init);
module_exit(switch_exit);
