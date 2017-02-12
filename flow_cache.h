#ifndef __H_FLOW_CACHE__
#define __H_FLOW_CACHE__

#include <linux/hashtable.h>
#include <linux/in.h>

struct fc_entry
{
    // hashtable node
    struct hlist_node hn;
    // ip addresses
    uint64_t key;
    // flow info
    uint8_t value;
};

// init and exit of flow cache
extern void fc_init();
extern void fc_exit();

// insert an entry
extern void fc_insert(uint64_t key, uint8_t value);

// get an entry
extern struct fc_entry* fc_get(uint64_t key);

// remove an key
extern void fc_remove(struct fc_entry *);

// generate a key using ip addresses
extern uint64_t get_key(unsigned char *);

#endif

