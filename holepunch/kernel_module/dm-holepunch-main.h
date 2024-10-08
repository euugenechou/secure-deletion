#ifndef HOLEPUNCH_MAIN
#define HOLEPUNCH_MAIN

#include <crypto/hash.h>
#include <crypto/rng.h>
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <linux/semaphore.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/sock.h>
/* #include <net/genetlink.h> */

#include "pprf-tree.h"

#define DM_MSG_PREFIX "holepunch"

#define ERASER_SECTOR 4096 /* In bytes. */
#define ERASER_HW_SECTOR 512 /* In bytes. */
#define ERASER_SECTOR_SCALE (ERASER_SECTOR / ERASER_HW_SECTOR)

#define ERASER_HEADER_LEN 1 /* In blocks. */
#define HOLEPUNCH_KEY_LEN 32 /* In bytes. */
#define ERASER_IV_LEN 16 /* In bytes. */
#define ERASER_SALT_LEN 32 /* In bytes. */
#define ERASER_DIGEST_LEN 32 /* In bytes. */
#define ERASER_NAME_LEN 16 /* ERASER instance name. */
/* 64 should be large enough for most purposes and may in fact be too large. */
#define HP_JOURNAL_LEN 64 /* In blocks. */
#define HP_HASH_LEN 32 /* In bytes. */

/* Crypto operations. */
#define HOLEPUNCH_ENCRYPT 1
#define HOLEPUNCH_DECRYPT 2

/* Cache flags & constants. */
#define ERASER_CACHE_DIRTY 0x000000001

/*
 * Memory pools.
 * TODO: These are quite large, could be reduced later after a
 * proper analysis of the actual requirements.
 */
#define ERASER_BIOSET_SIZE 1024
#define ERASER_PAGE_POOL_SIZE 1024
#define ERASER_IO_WORK_POOL_SIZE 1024
#define ERASER_UNLINK_WORK_POOL_SIZE 1024
#define ERASER_MAP_CACHE_POOL_SIZE 1024

/* Return codes. */
#define ERASER_SUCCESS 0
#define ERASER_ERROR 1

/* /proc file listing mapped ERASER devices. */
#define HOLEPUNCH_PROC_FILE "holepunchtab"

#define KWORKERMSG(msg, arg...)            \
    do {                                   \
        printk(                            \
            KERN_INFO "[%u/%u] " msg "\n", \
            task_pid_nr(current),          \
            get_cpu(),                     \
            ##arg                          \
        );                                 \
        put_cpu();                         \
    } while (0)

#ifdef HOLEPUNCH_SEMA
    #define HP_DOWN_WRITE(rwsem, msg, arg...)           \
        do {                                            \
            KWORKERMSG("TRY write rwsem: " msg, ##arg); \
            down_write(rwsem);                          \
            KWORKERMSG("GET write rwsem: " msg, ##arg); \
        } while (0)
    #define HP_UP_WRITE(rwsem, msg, arg...)             \
        do {                                            \
            up_write(rwsem);                            \
            KWORKERMSG("PUT write rwsem: " msg, ##arg); \
        } while (0)
    #define HP_DOWN_READ(rwsem, msg, arg...)           \
        do {                                           \
            KWORKERMSG("TRY read rwsem: " msg, ##arg); \
            down_read(rwsem);                          \
            KWORKERMSG("GET read rwsem: " msg, ##arg); \
        } while (0)
    #define HP_UP_READ(rwsem, msg, arg...)             \
        do {                                           \
            up_read(rwsem);                            \
            KWORKERMSG("PUT read rwsem: " msg, ##arg); \
        } while (0)
    #define HP_DOWNGRADE_WRITE(rwsem, msg, arg...)      \
        do {                                            \
            downgrade_write(rwsem);                     \
            KWORKERMSG("DOWNGRADE rwsem: " msg, ##arg); \
        } while (0)
    #define HP_DOWN(sem, msg, arg...)           \
        do {                                    \
            KWORKERMSG("TRY sem: " msg, ##arg); \
            down(sem);                          \
            KWORKERMSG("GET sem: " msg, ##arg); \
        } while (0)
    #define HP_UP(sem, msg, arg...)             \
        do {                                    \
            up(sem);                            \
            KWORKERMSG("PUT sem: " msg, ##arg); \
        } while (0)
#else
    #define HP_DOWN_WRITE(rwsem, msg, arg...) down_write(rwsem)
    #define HP_UP_WRITE(rwsem, msg, arg...) up_write(rwsem)
    #define HP_DOWN_READ(rwsem, msg, arg...) down_read(rwsem)
    #define HP_UP_READ(rwsem, msg, arg...) up_read(rwsem)
    #define HP_DOWNGRADE_WRITE(rwsem, msg, arg...) downgrade_write(rwsem);
    #define HP_DOWN(sem, msg, arg...) down(sem)
    #define HP_UP(sem, msg, arg...) up(sem)
#endif

struct holepunch_key {
    u8 key[HOLEPUNCH_KEY_LEN];
};

#define HP_KEY_PER_SECTOR ((ERASER_SECTOR - 32) / HOLEPUNCH_KEY_LEN)
#define HP_PPRF_PER_SECTOR (ERASER_SECTOR / sizeof(struct pprf_keynode))
#define HP_FKT_PER_SECTOR ((ERASER_SECTOR - 16) / HOLEPUNCH_KEY_LEN)

/* Chosen at random because I couldn't think of enough fun values. */
#define HP_MAGIC1 0xbffb8ee808b32e40
#define HP_MAGIC2 0xec993fbb3ce4623a

/*
 * The padding is entirely unused, but AES complains if the total size is not
 * block size multiple, so we start encrypting and decrypting at magic1, which
 * is 16 bytes (one AES block) in.
 */
struct __attribute__((aligned(ERASER_SECTOR))) holepunch_filekey_sector {
    u64 tag;
    u64 padding;
    u64 magic1;
    u64 magic2;
    struct holepunch_key entries[HP_KEY_PER_SECTOR];
};

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_keynode_sector {
    struct pprf_keynode entries[HP_PPRF_PER_SECTOR];
};

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_fkt_sector {
    /* The current number of keynodes in the PPRF key. */
    u32 pprf_size;
    u64 tag_counter;
    u32 padding;
    struct holepunch_key entries[HP_FKT_PER_SECTOR];
};

/* Holepunch header; must match the definition in userspace.
 * The kernel module should treat this as read-only
 */
struct holepunch_header {
    u8 enc_key[HOLEPUNCH_KEY_LEN]; /* Encrypted sector encryption key. */
    u8 enc_key_digest[ERASER_DIGEST_LEN]; /* Key digest. */
    u8 enc_key_salt[ERASER_SALT_LEN]; /* Key salt. */
    u8 pass_salt[ERASER_SALT_LEN]; /* Password salt. */
    u64 nv_index; /* Master key TPM NVRAM index. */

    /* IV generation key. TODO should this be encrypted? */
    u8 iv_key[HOLEPUNCH_KEY_LEN];

    /* All in ERASER sectors, strictly consecutive; header starts at zero. */
    u64 journal_start;
    u64 key_table_start;
    u64 fkt_start;
    u64 pprf_start;
    u64 data_start;
    u64 data_end; /* One past the last accesible data sector. */

    /* We use a two-level FKT; number of sectors in each level. */
    u64 fkt_top_width;
    u64 fkt_bottom_width;

    /* The maximum number of keynodes we can store on disk. */
    u32 pprf_capacity;

    /* The maximum PPRF depth. */
    u8 pprf_depth;
    u8 in_use;

    /* tag_counter and pprf_size are stored in the top-level FKT block
	 * since they are mutable - this helps save an IO op */
};

/*
 * The journal control block is only 512 bytes in size, but takes up the whole
 * first block of the journal. It begins with a u64 specifying the type of the
 * journal entry; further contents are determined by the type:
 */

enum {
    /* No active journal entry. */
    HPJ_NONE = 0,
    /* Master key rotation. Following the type is the new master key, encrypted by
	 * the old master key, followed by the hash of the old key. Recovery proceeds
	 * by comparing the hash of the current master key to the stored hash. If they
	 * match, pprf_fkt_top_width blocks should be copied from the journal to
	 * pprf_fkt_start in sequence, then the new key written to the TPM (obtained
	 * via decrypting the on-disc version), and finally the journal cleared. If they
	 * don't match, the journal can simply be cleared.
	 */
    HPJ_MASTER_ROT,
    /* PPRF key rotation. Following the type is the new PPRF key encrypted by the
	 * master key. Recovery includes walking the key table, decrypting each under
	 * the new PPRF until a magic byte mismatch, then switching to the on-disk PPRF.
	 * This process also includes resetting the tags and re-encrypting under the new
	 * PPRF. Following that, the FKT is filled with random bytes (via AES-CTR) and
	 * synced in memory, and the new PPRF key is written. Finally, tag_counter and
	 * pprf_key_size are reset and a master key rotation is scheduled.
	 */
    HPJ_PPRF_ROT,
    /*
	 * PPRF key initialization. Everything is the same as above, except magic bytes
	 * are ignored and simply reset instead.
	 */
    HPJ_PPRF_INIT,
    /* */
    HPJ_PPRF_PUNCT,
    /*
	 * Generic multi-block atomic write. The type is followed by up to 63 64-bit
	 * block addresses. Recovery proceeds by writing each block in the journal to
	 * its address (specified in the control block), then clearing the journal. An
	 * address corresponding to the control block indicates the end of valid
	 * addresses.
	 */
    HPJ_GENERIC
};

/*
 * Map entry and cache structs.
 */

#define ERASER_MAP_CACHE_BUCKETS 1024

struct eraser_map_cache {
    u64 sector;
    u64 status;
    unsigned long last_dirty;
    unsigned long last_access;
    unsigned long first_access;
    struct holepunch_filekey_sector *map;
    struct list_head list;
};

/* Master key status flags. */
enum {
    ERASER_KEY_GOT_KEY = 1,
    ERASER_KEY_GET_REQUESTED,
    ERASER_KEY_SET_REQUESTED,
    ERASER_KEY_SLOT_MAP_DIRTY,
    ERASER_KEY_READY_TO_REFRESH,
};

/* Represents a ERASER instance. */
struct holepunch_dev {
    char eraser_name[ERASER_NAME_LEN + 1]; /* Instance name. */
    struct dm_dev *real_dev; /* Underlying block device. */
    dev_t virt_dev; /* Virtual device-mapper node. */
    u8 *real_dev_path;
    u8 *virt_dev_path;

    u8 *sec_key; /* Sector encryption key. */
    u8 master_key[HOLEPUNCH_KEY_LEN]; /* File encryption master key. */
    u8 new_master_key
        [HOLEPUNCH_KEY_LEN]; /* Temporary key before syncing to TPM. */
    struct completion master_key_wait;
    unsigned long master_key_status; /* Key status flags. */
    int helper_pid; /* Netlink talks to this pid. */
    u64 *journal;
    int journal_entry;

    struct holepunch_header *hp_h;
    /* Some convenience lengths, calculated from the header. */
    u64 key_table_len;
    u64 fkt_len;
    u64 pprf_len;
    u64 data_len;

    struct pprf_keynode *pprf_key;
    u32 pprf_key_capacity;
    struct holepunch_pprf_fkt_sector *pprf_fkt;
    struct rw_semaphore pprf_sem;
    struct pprf_keynode pprf_key_new;

    /* Cache-related. */
    struct list_head map_cache_list[ERASER_MAP_CACHE_BUCKETS];
    struct semaphore cache_lock[ERASER_MAP_CACHE_BUCKETS];
    u64 map_cache_count;
    struct rw_semaphore map_cache_count_sem;
    struct task_struct *evict_map_cache_thread;

    /* Crypto transforms. */
    unsigned cpus;
    // EUGEBE: struct crypto_blkcipher swapped out for struct crypto_skcipher
    struct crypto_skcipher **ecb_tfm; /* AES-ECB for PRG and keys. */
    struct crypto_skcipher **cbc_tfm; /* AES-CBC for files and sectors. */
    struct crypto_skcipher *ctr_tfm; /* Single AES-CTR for PPRF rotation. */
    struct crypto_shash *sha_tfm; /* SHA256 for master key rotation. */
    u8 *prg_input; /* Input for length-doubling PRG. */

    /* Work queues. */
    struct workqueue_struct *io_queue;
    struct workqueue_struct *unlink_queue;

    atomic_t shutdown;
    atomic_t jobs;

    /* Memory pools. */
    struct bio_set bioset;
    mempool_t *page_pool;
    struct kmem_cache *_io_work_pool;
    mempool_t *io_work_pool;
    struct kmem_cache *_unlink_work_pool;
    mempool_t *unlink_work_pool;
    struct kmem_cache *_map_cache_pool;
    mempool_t *map_cache_pool;

    struct list_head list;

    /* Usage stats */
    u64 stats_evaluate;
    u64 stats_puncture;
    u64 stats_refresh;
#ifdef HOLEPUNCH_DEBUG
    volatile unsigned state;
#endif
};

static LIST_HEAD(holepunch_dev_list); /* We keep all ERASERs in a list. */
static DEFINE_SEMAPHORE(holepunch_dev_lock, 1);

/* Represents an IO operation in flight. */
struct eraser_io_work {
    struct holepunch_dev *rd;
    struct bio *bio;
    unsigned is_file;
    struct work_struct work;
};

/* Represents an unlink operation in flight. */
struct eraser_unlink_work {
    struct holepunch_dev *rd;
    unsigned long ino;
    struct work_struct work;
};

#define HP_PPRF_EXPANSION_FACTOR 4

/* Cache eviction timeouts. TODO: Tweak these. */
/* All in jiffies. */
#define ERASER_CACHE_EXP_FIRST_ACCESS (60 * HZ)
#define ERASER_CACHE_EXP_LAST_ACCESS (15 * HZ)
#define ERASER_CACHE_EXP_LAST_DIRTY (5 * HZ)
#define ERASER_CACHE_MEMORY_PRESSURE 0

/* In seconds. */
#define ERASER_CACHE_EVICTION_PERIOD 5

// #pragma GCC push_options
// #pragma GCC optimize("O0")

// #pragma GCC pop_options

#endif
