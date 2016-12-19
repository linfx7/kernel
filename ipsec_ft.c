#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/in.h>

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
    // pointer of next hashtable
    struct ft_hashtable *next;
    // number of entries in this hashtable
    uint32_t num;
    // every ft_hashtable has a hashtable with n hlist_head
    // - n depends on the node
    // - for node x*y, it take the minor of 2^10 and 2^(x+y)
    // - struct hlist_head *ht;
    // take 2^14 as n
    // DECLARE_HASHTABLE(ht, 14);
    struct hlist_head hs[8192];
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
            init_nodes(&ift->nodes[i][j]);
        }
    }
    return 0;
}

void ipsec_ft_exit()
{
    // free all nodes
    int i, j;
    for (i = 0; i < 32; ++i)
        for (j = 0; j < 32; ++j)
            free_nodes(&ift->nodes[i][j]);
    kfree(ift);
}

void init_nodes(struct ft_node *node)
{
    node->ft_ht = NULL;
    node->ft_t = NULL;
    node->length = 0;
    node->total = 0;
}

void free_nodes(struct ft_node *node)
{
    // free hashtable nodes
    if (node->ft_ht)
    {
        struct ft_hashtable *tmp_fh, *this = node->ft_ht;
        while (this)
        {
            tmp_fh = this->next;
            free_hashtable(this);
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

void free_hashtable(struct ft_hashtable *this)
{
    // traverse hashtable
    int tmp_i;
    struct hlist_node *tmp_hn;
    struct ft_hashtable_entry *tmp_fhe;

    hash_for_each_safe(this->ht, tmp_i, tmp_hn, tmp_fhe, hn)
    {
        // delete entry from hashtable
        hash_del(&tmp_fhe->hn);
        // free entry space
        kfree(tmp_fhe);
    }
    // free the hashtable
    kfree(this);
}

int ipsec_ft_insert
(
    struct in_addr from,
    uint8_t        from_pre,
    struct in_addr to,
    uint8_t        to_pre,
    uint8_t        status
)
{
    if (!(from_pre == 32 && to_pre == 32))
    {
        struct ft_hashtable *this = ift->nodes[from_pre][to_pre].ft_ht;
        if (!this)
        {
            // the node has no ft_hashtable
            // add one
            this = (struct ft_hashtable *) kmalloc(sizeof(struct ft_hashtable), GFP_KERNEL);
            // allocate failed
            if (!this)
                return -1;
            init_hashtable(this);
            ift->nodes[i][j].length += 1;
        }
        if (this->num > HASHTABLE_THRESHOLD)
        {
            // more ft_hashtable is needed
            this->next = (struct ft_hashtable *) kmalloc(sizeof(struct ft_hashtable), GFP_KERNEL);
            this = this->next;
            // allocate failed
            if (!this)
                return -1;
            init_hashtable(this);
            ift->nodes[i][j].length += 1;
        }

        // construct hashtable entry
        struct ft_hashtable_entry tmp_fhe;
        tmp_fhe = (struct ft_hashtable_entry *) kmalloc(sizeof(struct ft_hashtable_entry), GFP_KERNEL);
        tmp_fhe->status = status;
        tmp_fhe->from = from;
        tmp_fhe->to = to;
        tmp_fhe->from_pre = from_pre;
        tmp_fhe->to_pre = to_pre;
        INIT_HLIST_NODE(tmp_fhe->hn);

        // add entry to hashtable
        // hashtable, &entry->hn, key
        hash_add(this->hs, tmp_fhe->hn, get_key(from, to));
        this->num += 1;
        ift->nodes[i][j].total += 1;
        return 0;
    }
    else
    {

    }
}

uint64_t get_key(in_addr from, in_addr to)
{
    return ((0x00000000ffffffff & from) << 32)
        |   (0x00000000ffffffff & to);
}





struct hlist_node *node = NULL;
DEFINE_HASHTABLE(test_hash, 16);

int fst_init(void)
{
    hash_init(test_hash);

    stu = (struct student *) kmalloc(sizeof(struct student), GFP_KERNEL);
    memset(stu, 0, sizeof(struct student));
    strncpy(stu->name, "alice", 5);
    stu->age = 10;
    INIT_HLIST_NODE(&stu->innode);
    hash_add(test_hash, &stu->innode, 0x0001);

    stu = (struct student *) kmalloc(sizeof(struct student), GFP_KERNEL);
    memset(stu, 0, sizeof(struct student));
    strncpy(stu->name, "alice", 5);
    stu->age = 11;
    INIT_HLIST_NODE(&stu->innode);
    hash_add(test_hash, &stu->innode, 0x0001);

    stu = (struct student *) kmalloc(sizeof(struct student), GFP_KERNEL);
    memset(stu, 0, sizeof(struct student));
    strncpy(stu->name, "bob", 5);
    stu->age = 10;
    INIT_HLIST_NODE(&stu->innode);
    hash_add(test_hash, &stu->innode, 0x0002);

    return 0;
}

void fst_exit(void)
{
    int i;
    hash_for_each(test_hash, i, stu, innode)
    {
        printk("Student: %s, %d years old.\n", stu->name, stu->age);
    }

    printk("=================\n");
    
    hash_for_each_possible(test_hash, stu, innode, 0x0001)
    {
        printk("Student: %s, %d years old.\n", stu->name, stu->age);
    }

    printk("=================\n");

    struct hlist_node tmp, *tstu;
    tstu = &tmp;
    hash_for_each_safe(test_hash, i, tstu, stu, innode)
    {
        hash_del(&stu->innode);
        kfree(stu);
    }

    if (hash_empty(test_hash))
    {
        printk("empty\n");
    }
}

