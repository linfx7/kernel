#ifndef __H_NETLINK_SENDER__
#define __H_NETLINK_SENDER__

#include <linux/netlink.h>

#define NETLINK_TEST 31

extern int netlink_init(void (*msg_handler)(char *msg));
extern void netlink_close(void);

extern int send_msg(char *msg, int len);
extern int send_msg_to(int pid, char *msg, int len);

extern void handle_input(struct sk_buff *skb);
extern void handle_hello(int pid);

#endif
