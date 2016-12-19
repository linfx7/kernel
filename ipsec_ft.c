#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/in.h>

#define HASHTABLE_THRESHOLD 6144

// every node restores a tupple
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
};

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

struct ft_hashtable
{
    // pointer of previous and next hashtable
    struct ft_hashtable *next;
    // number of entries in this hashtable
    uint32_t num;
    // every ft_hashtable has a hashtable with n hlist_head
    // - n depends on the node
    // - for node x*y, it take the minor of 2^10 and 2^(x+y)
    // - struct hlist_head *ht;
    // take 2^14 as n
    // DECLARE_HASHTABLE(ht, 14);
    struct hlist_head ht[8192];
};

struct ft_tree_entry
{
    struct in_addr from;
    struct in_addr to;
    // 0: has informed controller
    // 1: discard
    uint8_t        status;
};

struct ft_tree
{
    // number of entries in the tree
    int num;
};

struct ipsec_ft
{
    struct ft_node nodes[32][32];
};

struct ipsec_ft *ift = NULL;

int ipsec_ft_init()
{
    ift = (struct ipsec_ft *) kmalloc(sizeof(struct ipsec_ft), GFP_KERNEL);
    if (!ift)
    {
        printk(KERN_ALERT "[!] Init IPsec-FT error!\n");
    }
    int i, j;
    for (i = 0; i < 32; ++i)
    {
        for (j = 0; j < 32; ++j)
        {
            init_node(&ift->nodes[i][j]);
        }
    }
    return 0;
}

void ipsec_ft_exit()
{
    // free all nodes
    int i, j;
    for (i = 0; i < 32; ++i)
    {
        for (j = 0; j < 32; ++j)
        {
            clear_node(&ift->nodes[i][j]);
        }
    }
    kfree(ift);
}

void init_node(struct ft_node *node)
{
    node->ft_ht = NULL;
    node->ft_t = NULL;
    node->length = 0;
    node->total = 0;
}

void clear_node(struct ft_node *node)
{
    // free hashtable nodes
    if (node->ft_ht)
    {
        struct ft_hashtable *tmp_fh, *this = node->ft_ht;
        while (this)
        {
            tmp_fh = this->next;
            clear_hashtable(this);
            // free the hashtable
            kfree(this);
            this = tmp_fh;
        }
    }
    if (node->ft_t)
    {
        // TODO free tree

    }
}

void init_hashtable(struct ft_hashtable *this)
{
    this->next = NULL;
    hash_init(this->ht);
    this->num = 0;
}

void clear_hashtable(struct ft_hashtable *this)
{
    // traverse hashtable
    int tmp_i;
    struct hlist_node *tmp_hn;
    struct ft_hashtable_entry *tmp_fhe;

    hash_for_each_safe(this->ht, tmp_i, tmp_hn, tmp_fhe, hn)
    {
        // delete entry from hashtable
        hash_del(&tmp_fhe->hn);
        // free the entry
        kfree(tmp_fhe);
    }
}

int ipsec_ft_insert(
        struct in_addr from,
        uint8_t        from_pre,
        struct in_addr to,
        uint8_t        to_pre,
        uint8_t        status
        )
{
    if (from_pre == 32 && to_pre == 32)
    {
        // insert to ft_tree
        // TODO
        return -1;
    }
    else
    {
        // construct hashtable entry
        struct ft_hashtable_entry *tmp_fhe;
        tmp_fhe = (struct ft_hashtable_entry *) kmalloc(sizeof(struct ft_hashtable_entry), GFP_KERNEL);
        tmp_fhe->status = status;
        tmp_fhe->from = from;
        tmp_fhe->to = to;
        tmp_fhe->from_pre = from_pre;
        tmp_fhe->to_pre = to_pre;
        INIT_HLIST_NODE(tmp_fhe->hn);
        // insert to ft_hashtable
        return insert_to_hashtable_node(&ift->nodes[from_pre][to_pre], tmp_fhe);
    }
}

void ipsec_ft_hashtable_del(struct ft_node *node,
        struct ft_hashtable *fth, struct ft_hashtable_entry *entry)
{
    hash_del(entry->hn);
    node->total -= 1;
    fth->num -= 1;
    // TODO compact

}

int insert_to_hashtable_node(struct ft_node *node, struct ft_hashtable_entry *entry)
{
    struct ft_hashtable *this = node->ft_ht;

    // the node has no ft_hashtable
    if (!this)
    {
        // add one
        this = (struct ft_hashtable *) kmalloc(sizeof(struct ft_hashtable), GFP_KERNEL);
        // allocate failed
        if (!this)
            return -1;
        init_hashtable(this);
        node->length += 1;
    }

    // go to the first insertable ft_hashtable
    // or go to the last ft_hashtable
    while(this->num >= HASHTABLE_THRESHOLD)
    {
        if (this->next)
            // next not null
            this = this->next;
        else
            // next is null -> this is the last one
            break;
    }

    // the last ft_hashtable is still not insertable
    if (this->num >= HASHTABLE_THRESHOLD)
    {
        // more ft_hashtable is needed
        this->next = (struct ft_hashtable *) kmalloc(sizeof(struct ft_hashtable), GFP_KERNEL);
        this = this->next;
        // allocate failed
        if (!this)
            return -1;
        init_hashtable(this);
        node->length += 1;
    }

    // add entry to hashtable
    // hashtable, &entry->hn, key
    hash_add(this->ht, entry->hn, get_key(entry->from, entry->to));
    this->num += 1;
    ift->nodes[i][j].total += 1;
    return 0;
}

uint64_t get_key(in_addr from, in_addr to)
{
    return ((0x00000000ffffffff & from) << 32)
        |   (0x00000000ffffffff & to);
}





