#include "netlink_kernel.h"
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NF_IP_PRE_ROUTING 0
#define NF_IP_LOCAL_IN 1
#define NF_IP_FORWARD 2
#define NF_IP_LOCAL_OUT 3
#define NF_IP_POST_ROUTING 4
#define NF_IP_NUMHOOKS 5

struct nf_hook_ops pr_nfho; //net filter hook option struct

struct socket *c_sock = NULL;

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    unsigned char* iphdr = skb_network_header(skb);
    if (iphdr != NULL 
            && (iphdr[16] == 127 && iphdr[17] == 0 
                && iphdr[18] == 0 && iphdr[19] == 1))
    {
        send_msg("one packet");
        //printk("ONE PACKET\n");
    }
    return NF_DROP;
}

void init_nfho(void)
{
    pr_nfho.hook = hook_func;
    pr_nfho.hooknum = NF_IP_POST_ROUTING;
    pr_nfho.pf = PF_INET;
    pr_nfho.priority = NF_IP_PRI_LAST;

    nf_register_hook(&pr_nfho);
}

void exit_nfho(void)
{
    nf_unregister_hook(&pr_nfho);
}

void msg_handler(char *msg)
{
    char rtn[100] = "Receive message: ";
    strcpy(rtn+17, msg);
    send_msg(rtn);
}

int mod_init(void)
{
    printk(KERN_INFO "[+] Install IPsec Notification module.\n");
    netlink_init(msg_handler);
    init_nfho();
    return 0; // Non-zero return means that the module couldn't be loaded.
}

void mod_exit(void)
{
    exit_nfho();
    netlink_close();
    printk(KERN_INFO "[-] Remove up IPsec Notification module.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linfx7");
MODULE_DESCRIPTION("IPsec packet notification");

module_init(mod_init);
module_exit(mod_exit);

