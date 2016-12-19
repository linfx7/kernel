#include "netlink_kernel.h"
#include <linux/module.h>
#include <linux/netlink.h>
#include <net/sock.h>

struct sock *nl_sock = NULL;
struct sk_buff *skb_out = NULL;
int user_pid = -1;

void (*handle_msg)(char *msg) = NULL;

int netlink_init(void (*msg_handler)(char *msg))
{
    struct netlink_kernel_cfg cfg = {
        .input = handle_input,
    };
    nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    
    if (!nl_sock) 
    {
        printk(KERN_ALERT "[!] Netlink error!\n");
        return -10;
    }
    //printk(KERN_INFO "NETLINK SENDER STARTED!\n");

    handle_msg = msg_handler;
    return 0;
}

void netlink_close(void)
{
    if (nl_sock)
    {
        netlink_kernel_release(nl_sock);
        //printk(KERN_INFO "NETLINK SENDER CLOSED!\n");
    }
}

int send_msg(char *msg)
{
    if (user_pid == -1)
        return -10;
    else
        return send_msg_to(user_pid, msg);
}

int send_msg_to(int pid, char *msg)
{
    skb_out = nlmsg_new(strlen(msg), 0);
    struct nlmsghdr *nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, strlen(msg), 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strcpy(nlmsg_data(nlh), msg);
    netlink_unicast(nl_sock, skb_out, user_pid, 1);

    return 0;
}

void handle_input(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
    char *msg = (char *)nlmsg_data(nlh);
    if (strcmp(msg, "HELLO") == 0)
    {
        handle_hello(nlh->nlmsg_pid);
    }
    else
    {
        handle_msg(msg);
    }
}

void handle_hello(int pid)
{
    printk(KERN_INFO "[>] Received HELLO from: %d.\n", pid);
    user_pid = pid;
}

