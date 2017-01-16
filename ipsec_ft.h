#ifndef __H_IPSEC_FT__
#define __H_IPSEC_FT__

#include <linux/hashtable.h>
#include <linux/in.h>

// the threshold to create new hashtable
#define HASHTABLE_THRESHOLD_RATE 3/4

// each node restores a tupple
struct ft_node
{
    // every node has a list of hashtable
    // or a tree (the 32*32 node)
    struct ft_hashtable *ft_ht;
    struct ft_tree *ft_t;
    // number of hashtables
    // or number of trees
    uint32_t length;
    // total entries
    uint32_t total;
    // base size of hashtable
    uint32_t base;
};

// each ft_hashtable_entry contains a hashtable entry
struct ft_hashtable_entry
{
    // hashtable node
    struct hlist_node hn;
    // flow info
    struct in_addr from;
    uint8_t        from_pre;
    struct in_addr to;
    uint8_t        to_pre;
    // 0: has informed controller
    // 1: discard
    uint8_t        status;
};

// each ft_hashtable contains a hashtable
struct ft_hashtable
{
    // pointer of previous and next hashtable
    struct ft_hashtable *next;
    // number of entries in this hashtable
    uint32_t size;
    // max size
    uint32_t max_size;
    // every ft_hashtable has a hashtable with n hlist_head
    // n depends on the node
    // for node x*y, it take the minor of 2^12 and 2^(x+y)
    // struct hlist_head *ht;
    // - DECLARE_HASHTABLE(ht, 12);
    // allocate space when used
    struct hlist_head *ht;
};

// each ft_tree_entry contains a tree entry
struct ft_tree_entry
{
    struct in_addr from;
    struct in_addr to;
    // 0: has informed controller
    // 1: discard
    uint8_t        status;
};

// each ft_tree contains a tree
struct ft_tree
{
    // number of entries in the tree
    uint32_t size;
};

// the IPsec-FT
struct ipsec_ft
{
    struct ft_node nodes[32][32];
};

// init and exit of IPsec-FT
extern int ipsec_ft_init();
extern void ipsec_ft_exit();

// init a ft node which contains a list of ft_hashtable, memory must be allocated first
extern void init_node(struct ft_node *node, uint8_t basep);
// clear contant of a ft node, the node itself is not freed
extern void clear_node(struct ft_node *node);

// init a ft_hashtable which contains a hashtable, memory must be allocated first
extern int init_hashtable(struct ft_node *node, struct ft_hashtable *this);
// clear and free all the hashtable in this ft_hashtable, the ft_hashtable is not freed
extern void clear_hashtable(struct ft_hashtable *this);
// insert an entry to a specific node
extern int insert_to_hashtable_node(struct ft_node *node, struct ft_hashtable_entry *entry);

// generate a key using ip addresses
extern uint64_t get_key(struct in_addr from, struct in_addr to);

// insert an entry to the IPsec-FT
extern int ipsec_ft_insert(
        struct in_addr from,
        uint8_t        from_pre,
        struct in_addr to,
        uint8_t        to_pre,
        uint8_t        status
        );
// delete an entry from the IPsec-FT
extern void ipsec_ft_hashtable_del(struct ft_node *node,
        struct ft_hashtable *fth, struct ft_hashtable_entry *entry);
// traverse the IPsec-FT, the loop will break when "break;" is executed
// struct ft_node *node
// struct ft_hashtable *ht
// struct ft_hashtable_entry
// uint64_t key
#define for_each_ht_entry_in_node(node, ht, entry, key)                     \
    for (ht = node->ft_ht; entry == NULL && ht; ht = ht->next)              \
        hash_for_each_possible(ht, entry, hn, key)

#endif

