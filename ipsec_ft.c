#include "ipsec_ft.h"
#include <linux/slab.h>
#include <linux/hashtable.h>

struct ipsec_ft *ift = NULL;

int ipsec_ft_init()
{
    ift = (struct ipsec_ft *) kmalloc(sizeof(struct ipsec_ft), GFP_KERNEL);
    if (!ift)
    {
        printk(KERN_ALERT "[!] Init IPsec-FT error!\n");
    }
    uint8_t i, j;
    for (i = 0; i < 32; ++i)
    {
        for (j = 0; j < 32; ++j)
        {
            init_node(&ift->nodes[i][j], i+j);
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

void init_node(struct ft_node *node, uint8_t basep)
{
    node->ft_ht = NULL;
    node->ft_t = NULL;
    node->length = 0;
    node->total = 0;
    basep = (basep < 12) ? basep : 12;
    node->base = 1 << basep;
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

int init_hashtable(struct ft_node *node, struct ft_hashtable *this)
{
    uint32_t ht_size = node->base << node->length;
    this->next = NULL;
    this->ht = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * ht_size, GFP_KERNEL);
    if (!this->ht)
        return -1;
    
    // hash_init(this->ht)
    // same as hash_init,
    // HASH_SIZE(this-ht) is replaced by this->max_size
    __hash_init(this->ht, this->max_size);

    this->size = 0;
    this->max_size = ht_size;
    return 0;
}

void clear_hashtable(struct ft_hashtable *this)
{
    // traverse hashtable
    int tmp_i;
    struct hlist_node *tmp_hn;
    struct ft_hashtable_entry *tmp_fhe;

    // hash_for_each_safe(this->ht, tmp_i, tmp_hn, tmp_fhe, hn)
    // same function as hash_for_each_safe,
    // but the HASH_SIZE(this->ht) is replaced by this->max_size
    for (tmp_i = 0, tmp_fhe = NULL; tmp_fhe == NULL && tmp_i < this->max_size; tmp_i++)
        hlist_for_each_entry_safe(tmp_fhe, tmp_hn, &this->ht[tmp_i], hn)
        {
            // delete entry from hashtable
            hash_del(&tmp_fhe->hn);
            // free the entry
            kfree(tmp_fhe);
        }
        kfree(this->ht);
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
        INIT_HLIST_NODE(&tmp_fhe->hn);
        // insert to ft_hashtable
        return insert_to_hashtable_node(&ift->nodes[from_pre][to_pre], tmp_fhe);
    }
}

void ipsec_ft_hashtable_del(struct ft_node *node,
        struct ft_hashtable *fth, struct ft_hashtable_entry *entry)
{
    hash_del(&entry->hn);
    node->total -= 1;
    fth->size -= 1;
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
        // of hashtable init failed (init_hashtable returns -1)
        if (!this || init_hashtable(node, this))
            return -1;
        node->length += 1;
    }

    // go to the first insertable ft_hashtable
    // or go to the last ft_hashtable
    while(this->size >= this->max_size * HASHTABLE_THRESHOLD_RATE)
    {
        if (this->next)
            // next not null
            this = this->next;
        else
            // next is null -> this is the last one
            break;
    }

    // the last ft_hashtable is still not insertable
    if (this->size >= this->max_size * HASHTABLE_THRESHOLD_RATE)
    {
        // more ft_hashtable is needed
        this->next = (struct ft_hashtable *) kmalloc(sizeof(struct ft_hashtable), GFP_KERNEL);
        this = this->next;
        // allocate failed
        // of hashtable init failed (init_hashtable returns -1)
        if (!this || init_hashtable(node, this))
            return -1;
        node->length += 1;
    }

    // add entry to hashtable
    // hashtable, &entry->hn, key
    // hash_add(this->ht, &entry->hn, get_key(entry->from, entry->to))
    // same as hash_add, but HASH_BITS(this->ht) is replaced by ilog2(this->max_size)
    hlist_add_head(&entry->hn,
            &this->ht[hash_min(get_key(entry->from, entry->to), ilog2(this->max_size))]);

    this->size += 1;
    node->total += 1;
    return 0;
}

uint64_t get_key(struct in_addr from, struct in_addr to)
{
    return ((0x00000000ffffffff & (uint64_t)from.s_addr) << 32)
        |   (0x00000000ffffffff & (uint64_t)to.s_addr);
}



