#include "flow_cache.h"
#include <linux/slab.h>

DEFINE_HASHTABLE(fc, 14);

void fc_init()
{
    hash_init(fc);
}

void fc_exit() {
    int i;
    struct fc_entry *e;
    struct hlist_node *thn;
    hash_for_each_safe(fc, i, thn, e, hn)
    {
        hash_del(&e->hn);
        kfree(e);
    }
}

void fc_insert(uint64_t key, uint8_t value) {
    struct fc_entry *e = (struct fc_entry *) kmalloc(sizeof(struct fc_entry), GFP_KERNEL);
    e->key = key;
    e->value = value;
    INIT_HLIST_NODE(&e->hn);
    hash_add(fc, &e->hn, key);
}

struct fc_entry* fc_get(uint64_t key)
{
    struct fc_entry *e;
    hash_for_each_possible(fc, e, hn, key)
    {
        if (e->key == key)
        {
            return e;
        }
    }
    return NULL;
}

void fc_remove(struct fc_entry *e)
{
    hash_del(&e->hn);
}

uint64_t get_key(unsigned char* ips)
{
    return (((0x00000000000000ff & (uint64_t)ips[0]) << 56)
        |   ((0x00000000000000ff & (uint64_t)ips[1]) << 48)
        |   ((0x00000000000000ff & (uint64_t)ips[2]) << 40)
        |   ((0x00000000000000ff & (uint64_t)ips[3]) << 32)
        |   ((0x00000000000000ff & (uint64_t)ips[4]) << 24)
        |   ((0x00000000000000ff & (uint64_t)ips[5]) << 16)
        |   ((0x00000000000000ff & (uint64_t)ips[6]) << 8)
        |    (0x00000000000000ff & (uint64_t)ips[7])
        );
}

