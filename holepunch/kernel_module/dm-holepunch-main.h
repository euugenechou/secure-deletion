
#ifndef HOLEPUNCH_MAIN
#define HOLEPUNCH_MAIN

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <crypto/rng.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/netlink.h>
/* #include <net/genetlink.h> */
#include <linux/skbuff.h>

#include "pprf-tree.h"






#define DM_MSG_PREFIX "eraser"

#define ERASER_SECTOR 4096   /* In bytes. */
#define ERASER_HW_SECTOR 512 /* In bytes. */
#define ERASER_SECTOR_SCALE (ERASER_SECTOR / ERASER_HW_SECTOR)

#define ERASER_HEADER_LEN 1  /* In blocks. */
#define ERASER_KEY_LEN 32    /* In bytes. */
#define ERASER_IV_LEN 16     /* In bytes. */
#define ERASER_SALT_LEN 32   /* In bytes. */
#define ERASER_DIGEST_LEN 32 /* In bytes. */
#define ERASER_NAME_LEN 16   /* ERASER instance name. */

/* Crypto operations. */
#define ERASER_ENCRYPT 1
#define ERASER_DECRYPT 2

/* Cache flags & constants. */
#define ERASER_CACHE_DIRTY       0x000000001

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
#define ERASER_MAP_CACHE_FULL ERASER_MAP_CACHEPOOL_SIZE

/* Return codes. */
#define ERASER_SUCCESS 0
#define ERASER_ERROR 1

/* /proc file listing mapped ERASER devices. */
#define ERASER_PROC_FILE "erasertab"


struct holepunch_filekey_entry {
	u8 key[ERASER_KEY_LEN];
	u8 iv[ERASER_IV_LEN];
};

#define HOLEPUNCH_FILEKEYS_PER_SECTOR \
		((ERASER_SECTOR-8)/sizeof(struct holepunch_filekey_entry))

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_filekey_sector {
	u64 tag;
	struct holepunch_filekey_entry entries[HOLEPUNCH_FILEKEYS_PER_SECTOR];
};


struct holepunch_pprf_fkt_entry {
	u8 key[ERASER_KEY_LEN];
	u8 iv[ERASER_IV_LEN];
};

#define HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR \
		(ERASER_SECTOR/sizeof(struct pprf_keynode))
#define HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR \
		(ERASER_SECTOR/sizeof(struct holepunch_pprf_fkt_entry))

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_keynode_sector {
	struct pprf_keynode entries[HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR];
};

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_fkt_sector {
	struct holepunch_pprf_fkt_entry entries[HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR];
};



/* ERASER header. Must match the definition in the user space. */
struct holepunch_header {
	// not sure what to do with all theses
	u8 enc_key[ERASER_KEY_LEN];           /* Encrypted sector encryption key. */
	u8 enc_key_digest[ERASER_DIGEST_LEN]; /* Key digest. */
	u8 enc_key_salt[ERASER_SALT_LEN];     /* Key salt. */
	u8 pass_salt[ERASER_SALT_LEN];        /* Password salt. */
	u8 slot_map_iv[ERASER_IV_LEN];        /* IV for PPRF FKT encryption. */

	u64 nv_index; /* TPM NVRAM index to store the master key, unused on the
		       * kernel side. */

	/* All in ERASER sectors. */
	u64 len;
	u64 key_table_start;
	u64 key_table_len;
	u64 pprf_fkt_start;
	u64 pprf_fkt_len;
	u64 pprf_key_start;
	u64 pprf_key_len;
	u64 data_start;
	u64 data_len;

	u8 pprf_depth;
	u32 master_key_count; // how many individual keys make up the master key
	u32 master_key_limit;
	u64 tag;

	u32 pprf_fkt_top_width;
	u32 pprf_fkt_bottom_width;

	u8 prg_iv[PRG_INPUT_LEN];
};


/*
 * Map entry and cache structs.
 */
/* Size padded to 64 bytes, must be multiple of sector size. */
struct eraser_map_entry {
	u8 key[ERASER_KEY_LEN];
	u8 iv[ERASER_IV_LEN];
	u64 status;
	u64 padding;
};

#define ERASER_MAP_CACHE_BUCKETS 1024
#define ERASER_MAP_PER_SECTOR 64

struct eraser_map_cache {
	u64 slot_no;
	u64 status;
	unsigned long last_dirty;
	unsigned long last_access;
	unsigned long first_access;
	struct eraser_map_entry *map;
	struct list_head list;
};

/*
 * Random data generation with AES-CTR.
 */
/* Refresh keys after generating this much data. */
#define ERASER_PRNG_AESCTR_REFRESH_LEN 1048576 /* In bytes. */ /* 1 MB */
#define ERASER_PRNG_AESCTR_CHUNK_LEN 1  /* No of chunks to generate the data in. */

/*
 * Context for random data generation.
 */
struct eraser_rand_context {
	u8 *buf;
	u64 max_chunk;
	u64 cur_chunk;
	u64 max_byte;
	u64 cur_byte;
	struct crypto_blkcipher *tfm;
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
struct eraser_dev {
	char eraser_name[ERASER_NAME_LEN + 1]; /* Instance name. */
	struct dm_dev *real_dev;           /* Underlying block device. */
	dev_t virt_dev;                    /* Virtual device-mapper node. */
	u8 *real_dev_path;
	u8 *virt_dev_path;

	u8 *enc_key;                       /* Sector encryption key. */
	u8 master_key[ERASER_KEY_LEN];       /* File encryption master key. */
	u8 new_master_key[ERASER_KEY_LEN];   /* Temporary key before syncing to TPM. */
	struct completion master_key_wait;
	unsigned long master_key_status;   /* Key status flags. */
	int helper_pid;                    /* Netlink talks to this pid. */

	struct eraser_header *rh;            /* Header, basic metadata. */
	struct holepunch_header *hp_h;

	struct holepunch_pprf_keynode_sector *pprf_master_key;
	u32 pprf_master_key_capacity;
	struct holepunch_pprf_fkt_sector *pprf_fkt;

	struct eraser_map_entry *slot_map;   /* In-memory slot map. */
	struct holepunch_filekey_sector *key_table;
	struct list_head map_cache_list[ERASER_MAP_CACHE_BUCKETS];
	u64 map_cache_count;
	struct task_struct *evict_map_cache_thread;

	/* Per CPU crypto transforms for everything. We go full parallel. */
	unsigned cpus;
	struct crypto_blkcipher **tfm;    /* Sector and file encryption. */
	struct eraser_rand_context *rand;   /* AES-CTR context for random data. */
	struct crypto_cipher **essiv_tfm; /* IV derivation for sector encryption. */

	/* Work queues. */
	struct workqueue_struct *io_queue;
	struct workqueue_struct *unlink_queue;

	/* Memory pools. */
	struct bio_set *bioset;
	mempool_t *page_pool;
	struct kmem_cache *_io_work_pool;
	mempool_t *io_work_pool;
	struct kmem_cache *_unlink_work_pool;
	mempool_t *unlink_work_pool;
	struct kmem_cache *_map_cache_pool;
	mempool_t *map_cache_pool;

	/* Locks. */
	struct semaphore cache_lock[ERASER_MAP_CACHE_BUCKETS];

	struct list_head list;
};
static LIST_HEAD(eraser_dev_list); /* We keep all ERASERs in a list. */
static DEFINE_SEMAPHORE(eraser_dev_lock);




/* ERASER header. Must match the definition in the user space. */
struct eraser_header {

	u8 enc_key[ERASER_KEY_LEN];           /* Encrypted sector encryption key. */
	u8 enc_key_digest[ERASER_DIGEST_LEN]; /* Key digest. */
	u8 enc_key_salt[ERASER_SALT_LEN];     /* Key salt. */
	u8 pass_salt[ERASER_SALT_LEN];        /* Password salt. */
	u8 slot_map_iv[ERASER_IV_LEN];        /* IV for slot map encryption. */

	u64 nv_index; /* TPM NVRAM index to store the master key, unused on the
		       * kernel side. */

	/* All in ERASER sectors. */
	u64 len;
	u64 slot_map_start;
	u64 slot_map_len;
	u64 inode_map_start;
	u64 inode_map_len;
	u64 data_start;
	u64 data_len;
};

/* Represents an IO operation in flight. */
struct eraser_io_work {
        struct eraser_dev *rd;
        struct bio *bio;
	unsigned is_file;
        struct work_struct work;
};

/* Represents an unlink operation in flight. */
struct eraser_unlink_work {
        struct eraser_dev *rd;
	unsigned long inode_no;
        struct work_struct work;
};

static int eraser_set_master_key(struct eraser_dev *rd);

static inline void holepunch_write_header(struct eraser_dev *rd);
static inline struct holepunch_header *holepunch_read_header(struct eraser_dev *rd);


#define HOLEPUNCH_PPRF_EXPANSION_FACTOR 4
// in sectors
#define HOLEPUNCH_INITIAL_PPRF_SIZE 1 

static int holepunch_alloc_master_key(struct eraser_dev *rd, unsigned len);
static int holepunch_expand_master_key(struct eraser_dev *rd, unsigned factor);
static void holepunch_init_master_key(struct eraser_dev *rd);
struct pprf_keynode *holepunch_get_keynode_by_index(void* ptr, unsigned index);
static int holepunch_evaluate_at_tag(struct eraser_dev *rd, u64 tag, 
		struct crypto_blkcipher *tfm, u8* out);
static int holepunch_puncture_at_tag(struct eraser_dev *rd, u64 tag,
		struct crypto_blkcipher *tfm);

static inline struct holepunch_pprf_fkt_entry *holepunch_get_parent_entry_for_fkt_bottom_layer
		(struct eraser_dev *rd, unsigned index);
static inline unsigned holepunch_get_parent_sectorno_for_fkt_bottom_layer
		(struct eraser_dev *rd, unsigned index);
static int holepunch_alloc_pprf_fkt(struct eraser_dev *rd);
static void holepunch_init_pprf_fkt(struct eraser_dev *rd);

static void holepunch_write_pprf_fkt_bottom_sector(struct eraser_dev *rd,
		unsigned sector, struct crypto_blkcipher *tfm, char *map, bool fkt_refresh);
static void holepunch_write_pprf_fkt_top_sector(struct eraser_dev *rd, 
		unsigned sector, struct crypto_blkcipher *tfm, char *map, bool fkt_refresh);
static int holepunch_write_pprf_fkt(struct eraser_dev *rd);

static void holepunch_read_pprf_fkt(struct eraser_dev *rd);

#ifdef DEBUG
static void holepunch_print_master_key(struct eraser_dev *rd);
#endif


static inline struct holepunch_filekey_sector *holepunch_get_fkt_sector_for_inode (struct eraser_dev *rd, u64 ino);
static inline int holepunch_get_sector_index_for_inode (struct eraser_dev *rd, u64 ino);


static void holepunch_do_crypto_on_key_table_sector(struct eraser_dev *rd,
		 struct holepunch_filekey_sector *sector, u8 *key, u8 *iv, int op);
static struct holepunch_filekey_sector *holepunch_read_key_table(struct eraser_dev *rd);
static void holepunch_write_key_table_sector(struct eraser_dev *rd, unsigned sectorno);

static int holepunch_set_new_tpm_key(struct eraser_dev *rd);

static inline struct holepunch_pprf_fkt_entry *holepunch_get_pprf_fkt_entry_for_keynode_sector
	(struct eraser_dev *rd, unsigned index);
static inline unsigned holepunch_get_pprf_fkt_sectorno_for_keynode_sector
		(struct eraser_dev *rd, unsigned index);
static inline int holepunch_get_pprf_keynode_sector_for_keynode_index(struct eraser_dev *rd,
		int pprf_keynode_index);
static struct holepunch_pprf_keynode_sector *holepunch_read_pprf_key(struct eraser_dev *rd);
static int holepunch_write_pprf_key(struct eraser_dev *rd);
static int holepunch_write_pprf_key_sector(struct eraser_dev *rd, unsigned index, 
	struct crypto_blkcipher *tfm, char *map, bool fkt_refresh);
static int holepunch_refresh_pprf_key(struct eraser_dev *rd);


static void holepunch_get_key_for_inode(u64 inode_no, u8 *key, u8 *iv, struct eraser_dev *rd);

static inline struct holepunch_filekey_sector *holepunch_get_fkt_sector_for_inode 
		(struct eraser_dev *rd, u64 ino);
static inline int holepunch_get_sector_index_for_inode 
		(struct eraser_dev *rd, u64 ino);

static void holepunch_do_unlink(struct work_struct *work);



MODULE_AUTHOR("Wittmann Goh");
MODULE_DESCRIPTION("holepunch target - based off of ERASER");
MODULE_LICENSE("GPL");
#endif