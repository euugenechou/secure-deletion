/*
 * Copyright (C) 2018 Kaan Onarlioglu <www.onarlioglu.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * dm-eraser.c, ver.2018.02.11
 *
 * ERASER device-mapper target.
 */

#include <crypto/hash.h>
#include <crypto/rng.h>
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/fs.h>
#include <linux/gfp_types.h>
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
#include <linux/smp.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/sock.h>
/* #include <net/genetlink.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #include <crypto/internal/cipher.h>
#endif

#define DM_MSG_PREFIX "eraser"

#define ERASER_SECTOR 4096 /* In bytes. */
#define ERASER_HW_SECTOR 512 /* In bytes. */
#define ERASER_SECTOR_SCALE (ERASER_SECTOR / ERASER_HW_SECTOR)

#define ERASER_HEADER_LEN 1 /* In blocks. */
#define ERASER_KEY_LEN 32 /* In bytes. */
#define ERASER_IV_LEN 16 /* In bytes. */
#define ERASER_SALT_LEN 32 /* In bytes. */
#define ERASER_DIGEST_LEN 32 /* In bytes. */
#define ERASER_NAME_LEN 16 /* ERASER instance name. */

/* Crypto operations. */
#define ERASER_ENCRYPT 1
#define ERASER_DECRYPT 2

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
#define ERASER_MAP_CACHE_FULL ERASER_MAP_CACHEPOOL_SIZE

/* Return codes. */
#define ERASER_SUCCESS 0
#define ERASER_ERROR 1

/* /proc file listing mapped ERASER devices. */
#define ERASER_PROC_FILE "erasertab"

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
#define ERASER_PRNG_AESCTR_CHUNK_LEN \
    1 /* No of chunks to generate the data in. */

/*
 * Context for random data generation.
 */
struct eraser_rand_context {
    u8 *buf;
    u64 max_chunk;
    u64 cur_chunk;
    u64 max_byte;
    u64 cur_byte;
    struct crypto_skcipher *tfm;
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
    struct dm_dev *real_dev; /* Underlying block device. */
    dev_t virt_dev; /* Virtual device-mapper node. */
    u8 *real_dev_path;
    u8 *virt_dev_path;

    u8 *enc_key; /* Sector encryption key. */
    u8 master_key[ERASER_KEY_LEN]; /* File encryption master key. */
    u8 new_master_key
        [ERASER_KEY_LEN]; /* Temporary key before syncing to TPM. */
    struct completion master_key_wait;
    unsigned long master_key_status; /* Key status flags. */
    int helper_pid; /* Netlink talks to this pid. */

    struct eraser_header *rh; /* Header, basic metadata. */

    struct eraser_map_entry *slot_map; /* In-memory slot map. */
    struct list_head map_cache_list[ERASER_MAP_CACHE_BUCKETS];
    u64 map_cache_count;
    struct task_struct *evict_map_cache_thread;

    /* Per CPU crypto transforms for everything. We go full parallel. */
    unsigned cpus;
    struct crypto_skcipher **tfm; /* Sector and file encryption. */
    struct crypto_skcipher **pprf_tfm; /* AES-EBC for pprf PRG */
    struct eraser_rand_context *rand; /* AES-CTR context for random data. */
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
static DEFINE_SEMAPHORE(eraser_dev_lock, 1);

/* ERASER header. Must match the definition in the user space. */
struct eraser_header {
    u8 enc_key[ERASER_KEY_LEN]; /* Encrypted sector encryption key. */
    u8 enc_key_digest[ERASER_DIGEST_LEN]; /* Key digest. */
    u8 enc_key_salt[ERASER_SALT_LEN]; /* Key salt. */
    u8 pass_salt[ERASER_SALT_LEN]; /* Password salt. */
    u8 slot_map_iv[ERASER_IV_LEN]; /* IV for slot map encryption. */

    u8 file_iv_gen_key[ERASER_KEY_LEN]; /* Key for file iv generation*/

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

/* Decodes a hex encoded byte string. */
static u8 *eraser_hex_decode(u8 *hex) {
    u8 buf[3];
    u8 *s;
    unsigned len;
    unsigned i;

    buf[2] = '\0';
    len = strlen(hex) / 2;

    s = kmalloc(len, GFP_KERNEL);
    memset(s, 0, len);

    for (i = 0; i < len; ++i) {
        buf[0] = *hex++;
        buf[1] = *hex++;
        BUG_ON(kstrtou8(buf, 16, &s[i]) != 0);
    }

    return s;
}

/*
 * /proc file functions.
 */

/* Iterates over all eraser_devs and prints the instance info. */
static int eraser_list_mounts(struct seq_file *f, void *v) {
    struct eraser_dev *cur;

    down(&eraser_dev_lock);
    list_for_each_entry(cur, &eraser_dev_list, list) {
        seq_printf(
            f,
            "%s %s %s\n",
            cur->eraser_name,
            cur->real_dev_path,
            cur->virt_dev_path
        );
    }
    up(&eraser_dev_lock);

    return 0;
}

/* Open handler for the /proc file. */
static int eraser_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, eraser_list_mounts, NULL);
}

/* /proc file operations. */
static const struct proc_ops eraser_fops = {
    // .owner = THIS_MODULE,
    .proc_open = eraser_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * Memory pool management functions. Nothing to see here.
 */

static struct page *eraser_allocate_page(struct eraser_dev *rd) {
    struct page *p;

    p = mempool_alloc(rd->page_pool, GFP_KERNEL);
    if (!p)
        DMCRIT("Cannot allocate new page!");

    return p;
}

static inline void eraser_free_page(struct page *p, struct eraser_dev *rd) {
    mempool_free(p, rd->page_pool);
}

static void eraser_free_sector(void *s, struct eraser_dev *rd) {
    struct page *p;

    p = virt_to_page(s);
    kunmap(p);
    mempool_free(p, rd->page_pool);
}

static struct bio *
eraser_allocate_bio_multi_vector(int vec_no, struct eraser_dev *rd) {
    struct bio *b;

    b = bio_alloc_bioset(
        rd->real_dev->bdev,
        vec_no,
        0,  // TODO: idk what the default flags are
        GFP_KERNEL,
        rd->bioset
    );
    if (!b)
        DMCRIT("Cannot allocate new bio!");

    return b;
}

static struct bio *eraser_allocate_bio(struct eraser_dev *rd) {
    struct bio *b;

    b = eraser_allocate_bio_multi_vector(1, rd);
    if (!b)
        DMCRIT("Cannot allocate new bio!");

    return b;
}

static struct eraser_io_work *
eraser_allocate_io_work(struct bio *bio, struct eraser_dev *rd) {
    struct eraser_io_work *w;

    w = mempool_alloc(rd->io_work_pool, GFP_NOIO);
    if (!w) {
        DMCRIT("Cannot allocate new io work!");
    } else {
        w->bio = bio;
        w->rd = rd;
    }
    return w;
}

static inline void eraser_free_io_work(struct eraser_io_work *w) {
    mempool_free(w, w->rd->io_work_pool);
}

static struct eraser_unlink_work *
eraser_allocate_unlink_work(unsigned long inode_no, struct eraser_dev *rd) {
    struct eraser_unlink_work *w;

    w = mempool_alloc(rd->unlink_work_pool, GFP_ATOMIC);
    if (!w) {
        DMCRIT("Cannot allocate new unlink work!");
    } else {
        w->inode_no = inode_no;
        w->rd = rd;
    }
    return w;
}

static inline void eraser_free_unlink_work(struct eraser_unlink_work *w) {
    mempool_free(w, w->rd->unlink_work_pool);
}

static struct eraser_map_cache *eraser_allocate_map_cache(struct eraser_dev *rd
) {
    struct eraser_map_cache *c;

    c = mempool_alloc(rd->map_cache_pool, GFP_NOIO);
    if (!c)
        DMCRIT("Cannot allocate new map cache!");

    memset(c, 0, sizeof(*c));
    return c;
}

static inline void
eraser_free_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd) {
    mempool_free(c, rd->map_cache_pool);
}

/*
 * ERASER device management functions.
 */

/* Looks up a block device by path. */
static int __eraser_lookup_dev(char *dev_path, dev_t *dev) {
    // struct block_device *bdev;

    // bdev = lookup_bdev(dev_path);
    // if (IS_ERR(bdev))
    //     return ERASER_ERROR;

    // *dev = bdev->bd_dev;
    // bdput(bdev);

    // return ERASER_SUCCESS;

    return lookup_bdev(dev_path, dev) == 0 ? ERASER_SUCCESS : ERASER_ERROR;
}

/* Looks up a ERASER device by its underlying block device. */
static struct eraser_dev *eraser_lookup_dev(char *dev_path) {
    struct eraser_dev *cur;
    dev_t dev;

    if (__eraser_lookup_dev(dev_path, &dev) == ERASER_ERROR) {
        DMCRIT("Device lookup failed!");
        return NULL;
    }

    list_for_each_entry(cur, &eraser_dev_list, list) {
        if (cur->real_dev->bdev->bd_dev == dev)
            return cur;
    }

    return NULL;
}

/* Creates a new ERASER device. */
static struct eraser_dev *
eraser_create_dev(struct dm_target *ti, char *dev_path, char *name) {
    struct eraser_dev *rd;

    rd = kmalloc(sizeof(*rd), GFP_KERNEL);
    memset(rd, 0, sizeof(*rd));
    memcpy(rd->eraser_name, name, ERASER_NAME_LEN);
    rd->eraser_name[ERASER_NAME_LEN] = '\0';

    if (dm_get_device(
            ti,
            dev_path,
            dm_table_get_mode(ti->table),
            &rd->real_dev
        )) {
        kfree(rd);
        return NULL;
    }

    INIT_LIST_HEAD(&rd->list);
    list_add(&rd->list, &eraser_dev_list);

    return rd;
}

/* Destroys a ERASER device. */
static void eraser_destroy_dev(struct dm_target *ti, struct eraser_dev *rd) {
    list_del(&rd->list);
    dm_put_device(ti, rd->real_dev);
    kfree(rd);
}

/*
 * Disk I/O helpers.
 */

/*
 * Sync I/O helper for metadata operations.
 * @bdev: Block device.
 * @sector: Sector no on REAL device!
 * @rw: READ or WRITE
 * @write_buf: Data buffer to write. Ignored for reads.
 * @return: Buffer containing read data. Caller frees memory.
 */
static void *__eraser_rw_sector(
    struct block_device *bdev,
    u64 sector,
    int rw,
    void *write_buf,
    struct eraser_dev *rd
) {
    struct bio *bio;
    struct page *p;

    if (rw == WRITE && !write_buf) {
        DMCRIT("Write buffer is NULL, aborting");
        return NULL;
    }

    bio = eraser_allocate_bio(rd);
    bio->bi_bdev = bdev;
    bio->bi_iter.bi_sector = sector * ERASER_SECTOR_SCALE;

    if (rw == READ) {
        p = eraser_allocate_page(rd);
        // bio->bi_rw &= ~REQ_WRITE;
        bio->bi_opf &= ~REQ_OP_WRITE;
    } else {
        p = virt_to_page(write_buf);
        // bio->bi_rw |= REQ_WRITE;
        bio->bi_opf |= REQ_OP_WRITE;
    }

    BUG_ON(bio_add_page(bio, p, ERASER_SECTOR, 0) == 0);

    submit_bio_wait(bio);

    bio_put(bio);

    return kmap(p);
}

/* Shortcut for I/O on the underlying block device. */
static inline void *
eraser_rw_sector(u64 sector, int rw, void *write_buf, struct eraser_dev *rd) {
    return __eraser_rw_sector(rd->real_dev->bdev, sector, rw, write_buf, rd);
}

/* Reads and returns the ERASER header from disk. */
static inline struct eraser_header *eraser_read_header(struct eraser_dev *rd) {
    return (struct eraser_header *)eraser_rw_sector(0, READ, NULL, rd);
}

/* Writes the ERASER header back to disk. */
static inline void
eraser_write_header(struct eraser_header *rh, struct eraser_dev *rd) {
    eraser_rw_sector(0, WRITE, (char *)rh, rd);
}

/*
 * Random data helpers.
 */

/* Returns crypto-safe random bytes from kernel pool. */
static inline void eraser_get_random_bytes_kernel(u8 *data, u64 len) {
    crypto_get_default_rng();
    crypto_rng_get_bytes(crypto_default_rng, data, len);
    crypto_put_default_rng();
}

/* Sets a new random AES-CTR key if necessary and refreshes the random data
 * buffer. */
static void eraser_fill_rand_buf(struct eraser_rand_context *rand) {
    // EUGEBE: Not sure why this doesn't use ERASER_KEY_LEN.
    u8 key[32];
    u8 null_iv[ERASER_IV_LEN] = {0};
    struct scatterlist src;
    struct scatterlist dst;
    struct skcipher_request *req;
    int ret;
    // struct blkcipher_desc desc;

    /* Refresh the key. */
    if (rand->cur_chunk == rand->max_chunk) {
        eraser_get_random_bytes_kernel(key, 32);
        // crypto_blkcipher_setkey(rand->tfm, key, 32);
        crypto_skcipher_setkey(rand->tfm, key, 32);
        memset(key, 0, 32);

        rand->cur_chunk = 0;
    }

    // EUGEBE: We can just use sg_init_one() here.
    // sg_init_table(&src, 1);
    // sg_init_table(&dst, 1);
    // sg_set_buf(&src, rand->buf, rand->max_byte);
    // sg_set_buf(&dst, rand->buf, rand->max_byte);
    sg_init_one(&src, rand->buf, rand->max_byte);
    sg_init_one(&dst, rand->buf, rand->max_byte);

    DECLARE_CRYPTO_WAIT(wait);

    req = skcipher_request_alloc(rand->tfm, GFP_KERNEL);
    skcipher_request_set_crypt(req, &src, &dst, rand->max_byte, null_iv);

    // desc.tfm = rand->tfm;
    // desc.flags = 0;

    // EUGEBE: crypto_blkcipher_encrypt() was synchronous.
    // if (crypto_blkcipher_encrypt(&desc, &dst, &src, rand->max_byte))
    //     DMCRIT("Error generating random stream");
    ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (ret != 0) {
        DMCRIT("Error generating random stream");
    }

    ++(rand->cur_chunk);
    rand->cur_byte = 0;

    skcipher_request_free(req);
}

/* Generates random bytes using the passed AES-CTR context. */
static void eraser_get_random_bytes(u8 *data, u64 len, struct eraser_dev *rd) {
    u64 left;
    u64 read;
    struct eraser_rand_context *rand = &rd->rand[get_cpu()];

    while (len) {
        left = rand->max_byte - rand->cur_byte;
        if (!left)
            eraser_fill_rand_buf(rand);

        read = (left < len) ? left : len;

        memcpy(data, rand->buf + rand->cur_byte, read);
        data += read;
        rand->cur_byte += read;
        len -= read;
    }

    put_cpu();
}

/* Fills a buffer with a random IV. */
static inline void eraser_get_random_iv(u8 *iv, struct eraser_dev *rd) {
    eraser_get_random_bytes(iv, ERASER_IV_LEN, rd);
}

/* Fills a buffer with a random key. */
static inline void eraser_get_random_key(u8 *key, struct eraser_dev *rd) {
    eraser_get_random_bytes(key, ERASER_KEY_LEN, rd);
}

/*
 * Crypto functions.
 */

/* Convert one buffer of data. */
static void __eraser_do_crypto(
    struct scatterlist *src,
    struct scatterlist *dst,
    u64 len,
    u8 *key,
    u8 *iv,
    struct crypto_skcipher *tfm,
    int op,
    struct eraser_dev *rd
) {
    // struct blkcipher_desc desc;
    struct crypto_skcipher *local_tfm;
    struct skcipher_request *req;
    int ret;

    /*
   * We don't have explcit locks, but per cpu transforms. This means we
   * would be in trouble if we are converting more than one buffer,
   * calling this routine repeatedly, and the function gets scheduled on a
   * different CPU at some point. In that case, pass a separate TFM from
   * the outside, and per CPU transforms will be ignored.
   */
    local_tfm = tfm ? tfm : rd->tfm[get_cpu()];

    // if (tfm) {
    //     desc.tfm = tfm;
    // } else {
    //     desc.tfm = rd->tfm[get_cpu()];
    // }
    // desc.flags = 0;

    if (key)
        crypto_skcipher_setkey(local_tfm, key, ERASER_KEY_LEN);

    // if (iv) crypto_blkcipher_set_iv(desc.tfm, iv, ERASER_IV_LEN);

    // EUGEBE: We need to set the key first.
    req = skcipher_request_alloc(local_tfm, GFP_KERNEL);
    skcipher_request_set_crypt(req, src, dst, len, iv);

    DECLARE_CRYPTO_WAIT(wait);

    if (op == ERASER_ENCRYPT) {
        // if (crypto_blkcipher_encrypt(&desc, dst, src, len))
        //     DMCRIT("Error doing crypto");
        ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
        if (ret != 0) {
            DMCRIT("Error doing crypto (encrypting)");
        }
    } else if (op == ERASER_DECRYPT) {
        // if (crypto_blkcipher_decrypt(&desc, dst, src, len))
        //     DMCRIT("Error doing crypto");
        ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
        if (ret != 0) {
            DMCRIT("Error doing crypto (decrypting)");
        }
    } else {
        DMCRIT("Unknown crypto operation");
    }

    skcipher_request_free(req);

    // EUGEBE: put cpu back depending on passed in tfm.
    if (!tfm)
        put_cpu();
}

/* Convert between two buffers. */
static void eraser_do_crypto_between_buffers(
    char *from_buf,
    char *to_buf,
    u64 len,
    u8 *key,
    u8 *iv,
    struct crypto_skcipher *tfm,
    int op,
    struct eraser_dev *rd
) {
    struct scatterlist src;
    struct scatterlist dst;

    // EUGEBE: We can use sg_init_one() instead now.
    // sg_init_table(&src, 1);
    // sg_init_table(&dst, 1);
    // sg_set_buf(&src, from_buf, len);
    // sg_set_buf(&dst, to_buf, len);
    sg_init_one(&src, from_buf, len);
    sg_init_one(&dst, to_buf, len);

    __eraser_do_crypto(&src, &dst, len, key, iv, tfm, op, rd);
}

/* Convert between two pages. */
static void eraser_do_crypto_between_pages(
    struct page *from,
    struct page *to,
    unsigned offset,
    u64 len,
    u8 *key,
    u8 *iv,
    struct crypto_skcipher *tfm,
    int op,
    struct eraser_dev *rd
) {
    char *from_buf = ((char *)kmap(from)) + offset;
    char *to_buf = ((char *)kmap(to)) + offset;

    eraser_do_crypto_between_buffers(
        from_buf,
        to_buf,
        len,
        key,
        iv,
        tfm,
        op,
        rd
    );

    kunmap(from);
    kunmap(to);
}

/* Convert a data buffer in place. */
static inline void eraser_do_crypto_from_buffer(
    char *buf,
    u64 len,
    u8 *key,
    u8 *iv,
    struct crypto_skcipher *tfm,
    int op,
    struct eraser_dev *rd
) {
    eraser_do_crypto_between_buffers(buf, buf, len, key, iv, tfm, op, rd);
}

/* Convert a page in place. */
static void eraser_do_crypto_from_page(
    struct page *p,
    unsigned offset,
    u64 len,
    u8 *key,
    u8 *iv,
    struct crypto_skcipher *tfm,
    int op,
    struct eraser_dev *rd
) {
    char *buf = ((char *)kmap(p)) + offset;

    eraser_do_crypto_from_buffer(buf, len, key, iv, tfm, op, rd);

    kunmap(p);
}

/*
 * Map (i.e., key tree) and cache functions.
 */
/*
 * Reads sectors of slot entries. Used only for the slot map. For inode maps we
 * have a better optimized one exploiting the fact that they are always single
 * sector reads.
 */
static struct eraser_map_entry *eraser_read_slot_map(
    u64 start,
    u64 len,
    u8 *key,
    u8 *iv,
    struct eraser_dev *rd
) {
    struct crypto_skcipher *tfm;
    char *data;
    char *map;
    u64 i;

    /* Use a fresh tfm so that nothing breaks if this code gets scheduled on
   * different CPUs. */
    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);

    /* Could be big. */
    map = vmalloc(len * ERASER_SECTOR);

    /* Do crypto in chunks. Crypto API cannot work on vmalloc'd regions! */
    data = eraser_rw_sector(start, READ, NULL, rd);
    eraser_do_crypto_from_buffer(
        data,
        ERASER_SECTOR,
        key,
        iv,
        tfm,
        ERASER_DECRYPT,
        rd
    );
    memcpy(map, data, ERASER_SECTOR);
    eraser_free_sector(data, rd);

    for (i = 1; i < len; ++i) {
        data = eraser_rw_sector(start + i, READ, NULL, rd);
        eraser_do_crypto_from_buffer(
            data,
            ERASER_SECTOR,
            NULL,
            NULL,
            tfm,
            ERASER_DECRYPT,
            rd
        );
        memcpy(map + (i * ERASER_SECTOR), data, ERASER_SECTOR);
        eraser_free_sector(data, rd);
    }

    crypto_free_skcipher(tfm);

    return (struct eraser_map_entry *)map;
}

/* Writes the slot map back to disk. */
static void eraser_write_slot_map(
    struct eraser_map_entry *slot_map,
    u64 start,
    u64 len,
    u8 *key,
    u8 *iv,
    struct eraser_dev *rd
) {
    struct crypto_skcipher *tfm;
    struct page *p;
    char *map = (char *)slot_map;
    char *data;
    u64 i;

    /* Use a fresh tfm so that nothing breaks if this code gets scheduled on
   * different CPUs. */
    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    p = eraser_allocate_page(rd);
    data = kmap(p);

    /* Do crypto in chunks. Crypto API cannot work on vmalloc'd regions! */
    memcpy(data, map, ERASER_SECTOR);
    eraser_do_crypto_from_buffer(
        data,
        ERASER_SECTOR,
        key,
        iv,
        tfm,
        ERASER_ENCRYPT,
        rd
    );
    eraser_rw_sector(start, WRITE, data, rd);

    for (i = 1; i < len; ++i) {
        memcpy(data, map + (i * ERASER_SECTOR), ERASER_SECTOR);
        eraser_do_crypto_from_buffer(
            data,
            ERASER_SECTOR,
            NULL,
            NULL,
            tfm,
            ERASER_ENCRYPT,
            rd
        );
        eraser_rw_sector(start + i, WRITE, data, rd);
    }

    kunmap(p);
    eraser_free_page(p, rd);

    crypto_free_skcipher(tfm);
}

static inline u64 eraser_get_inode_offset(unsigned long inode_no) {
    return inode_no % ERASER_MAP_PER_SECTOR;
}

static inline u64 eraser_get_slot_no(unsigned long inode_no) {
    return inode_no / ERASER_MAP_PER_SECTOR;
}

/* Drop a cache entry. Lock from outside. */
static inline void
eraser_drop_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd) {
    list_del(&c->list);
    eraser_free_sector((char *)c->map, rd);
    eraser_free_map_cache(c, rd);
    rd->map_cache_count -= 1;
}

/* Write a cache entry back to disk. Lock from outside. */
static void
eraser_write_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd) {
    char *buf;
    struct page *p;

    p = eraser_allocate_page(rd);
    buf = kmap(p);

    eraser_do_crypto_between_buffers(
        (char *)c->map,
        buf,
        ERASER_SECTOR,
        rd->slot_map[c->slot_no].key,
        rd->slot_map[c->slot_no].iv,
        NULL,
        ERASER_ENCRYPT,
        rd
    );
    eraser_rw_sector(rd->rh->inode_map_start + c->slot_no, WRITE, buf, rd);
    c->status &= ~ERASER_CACHE_DIRTY;

    kunmap(p);
    eraser_free_page(p, rd);
}

/* Drops all cache entries, writes them back to disk if dirty. Locked from
 * inside. */
static void eraser_force_evict_map_cache(struct eraser_dev *rd) {
    struct eraser_map_cache *c;
    struct eraser_map_cache *n;
    int i;

    for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
        down(&rd->cache_lock[i]);
        list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list) {
            if (c->status & ERASER_CACHE_DIRTY)
                eraser_write_map_cache(c, rd);

            eraser_drop_map_cache(c, rd);
        }
        up(&rd->cache_lock[i]);
    }
}

/* Cache eviction timeouts. TODO: Tweak these. */
/* All in jiffies. */
#define ERASER_CACHE_EXP_FIRST_ACCESS (60 * HZ)
#define ERASER_CACHE_EXP_LAST_ACCESS (15 * HZ)
#define ERASER_CACHE_EXP_LAST_DIRTY (5 * HZ)
#define ERASER_CACHE_MEMORY_PRESSURE 0

/* In seconds. */
#define ERASER_CACHE_EVICTION_PERIOD 5

/* Cache eviction runs in separate kernel thread, periodically. */
static int eraser_evict_map_cache(void *data) {
    struct eraser_dev *rd = (struct eraser_dev *)data;
    struct eraser_map_cache *c;
    struct eraser_map_cache *n;
    int will_evict;
    int will_write_if_dirty;
    int i;

    /* unsigned long first_access_timeout; */
    unsigned long last_access_timeout;
    unsigned long last_dirty_timeout;

    while (1) {
        /* first_access_timeout = jiffies - ERASER_CACHE_EXP_FIRST_ACCESS; */
        last_access_timeout = jiffies - ERASER_CACHE_EXP_LAST_ACCESS;
        last_dirty_timeout = jiffies - ERASER_CACHE_EXP_LAST_DIRTY;

        for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
            down(&rd->cache_lock[i]);
            list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list) {
                will_evict = 0;
                will_write_if_dirty = 0;

                if (time_after(last_dirty_timeout, c->last_dirty))
                    will_write_if_dirty = 1;

                if (time_after(last_access_timeout, c->last_access))
                    will_evict = 1;

                if ((will_write_if_dirty || will_evict)
                    && (c->status & ERASER_CACHE_DIRTY)) {
                    eraser_write_map_cache(c, rd);
                }

                if (will_evict
                    && (rd->map_cache_count > ERASER_CACHE_MEMORY_PRESSURE))
                    eraser_drop_map_cache(c, rd);
            }
            up(&rd->cache_lock[i]);
        }

        /*
     * We do simple & stupid sleep wait instead of signaling. Proper
     * eviction strategies should be studied for optimal performance.
     */
        if (kthread_should_stop())
            return 0;

        msleep_interruptible(ERASER_CACHE_EVICTION_PERIOD * 1000);
    }

    return 0; /* Never. */
}

/* Search the cache for given keys. Lock from outside. */
static struct eraser_map_cache *
eraser_search_map_cache(u64 slot_no, int bucket, struct eraser_dev *rd) {
    struct eraser_map_cache *c;

    list_for_each_entry(c, &rd->map_cache_list[bucket], list) {
        if (c->slot_no == slot_no) {
            c->last_access = jiffies;
            return c;
        }
    }

    return NULL; /* Not found. */
}

/* Read from disk the given keys, and cache. Lock from outside. */
static struct eraser_map_cache *
eraser_cache_map(u64 slot_no, int bucket, struct eraser_dev *rd) {
    struct eraser_map_cache *c;

    /* Read map entries from disk. */
    c = eraser_allocate_map_cache(rd);
    c->map =
        eraser_rw_sector(rd->rh->inode_map_start + slot_no, READ, NULL, rd);
    eraser_do_crypto_from_buffer(
        (char *)c->map,
        ERASER_SECTOR,
        rd->slot_map[slot_no].key,
        rd->slot_map[slot_no].iv,
        NULL,
        ERASER_DECRYPT,
        rd
    );

    /* Set up the rest of the cache entry. */
    c->slot_no = slot_no;
    c->status = 0;
    c->first_access = jiffies;
    c->last_access = jiffies;

    /* Add to cache. */
    INIT_LIST_HEAD(&c->list);
    list_add(&c->list, &rd->map_cache_list[bucket]);
    rd->map_cache_count += 1;

    return c;
}

/* Retrieve the inode metadata from disk or cache. */
static void eraser_get_inode_map_entry(
    unsigned long inode_no,
    struct eraser_dev *rd,
    struct eraser_map_entry *out
) {
    struct eraser_map_cache *c;
    u64 slot_no;
    int bucket;

    slot_no = eraser_get_slot_no(inode_no);
    bucket = slot_no % ERASER_MAP_CACHE_BUCKETS;

    down(&rd->cache_lock[bucket]);
    c = eraser_search_map_cache(slot_no, bucket, rd);
    if (!c) {
        c = eraser_cache_map(slot_no, bucket, rd);
    }

    /* Return a copy of the inode map entry. */
    memcpy(out, &c->map[eraser_get_inode_offset(inode_no)], sizeof(*out));
    up(&rd->cache_lock[bucket]);
}

/* Get the inode key and iv. */
static void eraser_get_key_for_inode(
    unsigned long inode_no,
    u8 *key,
    u8 *iv,
    struct eraser_dev *rd
) {
    struct eraser_map_entry inode_map;

    eraser_get_inode_map_entry(inode_no, rd, &inode_map);
    memcpy(key, inode_map.key, ERASER_KEY_LEN);
    memcpy(iv, inode_map.iv, ERASER_IV_LEN);
}

/*
 * I/O mapping & encryption/decryption functions.
 */

/* Called when an encrypted clone bio is written to disk. */
static void eraser_encrypted_bio_end_io(struct bio *encrypted_bio) {
    struct bio_vec vec;
    struct eraser_io_work *w =
        (struct eraser_io_work *)encrypted_bio->bi_private;

    encrypted_bio->bi_iter = w->bio->bi_iter;

    bio_endio(w->bio);
    bio_put(w->bio);

    while (encrypted_bio->bi_iter.bi_size) {
        vec = bio_iter_iovec(encrypted_bio, encrypted_bio->bi_iter);
        bio_advance_iter(encrypted_bio, &encrypted_bio->bi_iter, vec.bv_len);
        eraser_free_page(vec.bv_page, w->rd);
    }

    bio_put(encrypted_bio);
    eraser_free_io_work(w);
}

static void holepunch_aes_ecb(
    struct eraser_dev *rd,
    u8 *key,
    u8 *in,
    u8 *out,
    unsigned len
) {
    // struct blkcipher_desc desc;
    struct crypto_skcipher *tfm;
    struct scatterlist src, dst;
    struct skcipher_request *req;
    int ret;
    u8 null_iv[ERASER_IV_LEN] = {0};

    // desc.tfm = rd->pprf_tfm[get_cpu()];
    // desc.flags = 0;
    tfm = rd->pprf_tfm[get_cpu()];

    // EUGEBE: We can use sg_init_one() here.
    // sg_init_table(&src, 1);
    // sg_init_table(&dst, 1);
    // sg_set_buf(&src, in, len);
    // sg_set_buf(&dst, out, len);
    sg_init_one(&src, in, len);
    sg_init_one(&dst, out, len);

    DECLARE_CRYPTO_WAIT(wait);

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    skcipher_request_set_crypt(req, &src, &dst, len, null_iv);

    crypto_skcipher_setkey(tfm, key, len);

    // if (crypto_blkcipher_encrypt(&desc, &dst, &src, len))
    //     DMCRIT("Error doing crypto");
    ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (ret != 0) {
        DMCRIT("Error doing crypto");
    }

    put_cpu();
}

static void eraser_derive_file_iv(
    struct eraser_dev *rd,
    u8 *derived_iv,
    u8 *kiv,
    unsigned long index
) {
    memset(derived_iv, 0, ERASER_IV_LEN);
    *(unsigned long *)derived_iv = index;
    holepunch_aes_ecb(
        rd,
        rd->rh->file_iv_gen_key,
        derived_iv,
        derived_iv,
        ERASER_IV_LEN
    );
}

static void
eraser_derive_sector_iv(u8 *iv, unsigned long index, struct eraser_dev *rd) {
    *(unsigned long *)iv = index;

    crypto_cipher_encrypt_one(rd->essiv_tfm[get_cpu()], iv, iv);
    put_cpu();
}

/* Bottom-half entry for write operations. */
static void eraser_do_write_bottomhalf(struct eraser_io_work *w) {
    struct bio *clone;
    struct bio *encrypted_bio;
    struct bio_vec vec;
    struct page *p;
    u8 key[ERASER_KEY_LEN];
    u8 iv[ERASER_IV_LEN];
    u8 derived_iv[ERASER_IV_LEN];

    if (w->is_file) {
        eraser_get_key_for_inode(
            bio_iter_iovec(w->bio, w->bio->bi_iter)
                .bv_page->mapping->host->i_ino,
            key,
            iv,
            w->rd
        );
    } else {
        memcpy(key, w->rd->enc_key, ERASER_KEY_LEN);
        memset(iv, 0, ERASER_IV_LEN);
    }

    /* Clone the original bio's pages, encrypt them, submit in a new bio. */
    encrypted_bio = eraser_allocate_bio_multi_vector(
        w->bio->bi_iter.bi_size / ERASER_SECTOR,
        w->rd
    );
    encrypted_bio->bi_bdev = w->bio->bi_bdev;
    encrypted_bio->bi_iter.bi_sector = w->bio->bi_iter.bi_sector;
    // encrypted_bio->bi_rw = w->bio->bi_rw;
    encrypted_bio->bi_opf = w->bio->bi_opf;
    encrypted_bio->bi_private = w;
    encrypted_bio->bi_end_io = &eraser_encrypted_bio_end_io;

    // clone = bio_clone_fast(w->bio, GFP_NOIO, w->rd->bioset);
    clone = bio_alloc_clone(w->bio->bi_bdev, w->bio, GFP_NOIO, w->rd->bioset);
    while (clone->bi_iter.bi_size) {
        vec = bio_iter_iovec(clone, clone->bi_iter);
        bio_advance_iter(clone, &clone->bi_iter, vec.bv_len);

        if (w->is_file) {
            eraser_derive_file_iv(
                w->rd,
                derived_iv,
                iv,
                clone->bi_iter.bi_sector
            );
        } else {
            memcpy(derived_iv, iv, ERASER_IV_LEN);
            eraser_derive_sector_iv(
                derived_iv,
                clone->bi_iter.bi_sector,
                w->rd
            );
        }
        p = eraser_allocate_page(w->rd);
        eraser_do_crypto_between_pages(
            vec.bv_page,
            p,
            0,
            ERASER_SECTOR,
            key,
            derived_iv,
            NULL,
            ERASER_ENCRYPT,
            w->rd
        );
        BUG_ON(bio_add_page(encrypted_bio, p, ERASER_SECTOR, 0) == 0);
    }

    submit_bio(encrypted_bio);
    bio_put(clone);
}

/* Bottom half entry for read operations. */
static void eraser_do_read_bottomhalf(struct eraser_io_work *w) {
    struct bio *clone;
    struct bio_vec vec;
    u8 key[ERASER_KEY_LEN];
    u8 iv[ERASER_IV_LEN];
    u8 derived_iv[ERASER_IV_LEN];

    if (w->is_file) {
        eraser_get_key_for_inode(
            bio_iter_iovec(w->bio, w->bio->bi_iter)
                .bv_page->mapping->host->i_ino,
            key,
            iv,
            w->rd
        );
    } else {
        memcpy(key, w->rd->enc_key, ERASER_KEY_LEN);
        memset(iv, 0, ERASER_IV_LEN);
    }

    /* Read is complete at this point. Simply iterate over pages and
   * decrypt. */
    // clone = bio_clone_fast(w->bio, GFP_NOIO, w->rd->bioset);
    clone = bio_alloc_clone(w->bio->bi_bdev, w->bio, GFP_NOIO, w->rd->bioset);
    while (clone->bi_iter.bi_size) {
        vec = bio_iter_iovec(clone, clone->bi_iter);
        bio_advance_iter(clone, &clone->bi_iter, vec.bv_len);

        if (w->is_file) {
            eraser_derive_file_iv(
                w->rd,
                derived_iv,
                iv,
                clone->bi_iter.bi_sector
            );
        } else {
            memcpy(derived_iv, iv, ERASER_IV_LEN);
            eraser_derive_sector_iv(
                derived_iv,
                clone->bi_iter.bi_sector,
                w->rd
            );
        }
        eraser_do_crypto_from_page(
            vec.bv_page,
            0,
            ERASER_SECTOR,
            key,
            derived_iv,
            NULL,
            ERASER_DECRYPT,
            w->rd
        );
    }

    bio_endio(w->bio);
    bio_put(w->bio);

    bio_put(clone);
    eraser_free_io_work(w);
}

/* I/O queues. */
static void eraser_do_io(struct work_struct *work) {
    struct eraser_io_work *w = container_of(work, struct eraser_io_work, work);

    if (bio_data_dir(w->bio) == WRITE)
        eraser_do_write_bottomhalf(w);
    else
        eraser_do_read_bottomhalf(w);
}

static void eraser_queue_io(struct eraser_io_work *w) {
    INIT_WORK(&w->work, eraser_do_io);
    queue_work(w->rd->io_queue, &w->work);
}

/* Called when the original bio's read is complete. Next we wil decrypt in the
 * bottom half. */
static void eraser_read_end_io(struct bio *clone) {
    eraser_queue_io((struct eraser_io_work *)clone->bi_private);
    bio_put(clone);
}

/*
 * Unlink functions.
 */

/* Randomize key and IV of deleted inode. */
static inline void
eraser_refresh_map_entry(struct eraser_map_entry *m, struct eraser_dev *rd) {
    eraser_get_random_key(m->key, rd);
    eraser_get_random_iv(m->iv, rd);
    m->status |= ERASER_CACHE_DIRTY;
}

/* Bottom half for unlink operations. */
static void eraser_do_unlink(struct work_struct *work) {
    struct eraser_unlink_work *w =
        container_of(work, struct eraser_unlink_work, work);
    struct eraser_map_cache *c;
    u64 slot_no;
    int bucket;

    slot_no = eraser_get_slot_no(w->inode_no);
    bucket = slot_no % ERASER_MAP_CACHE_BUCKETS;

    down(&w->rd->cache_lock[bucket]);
    c = eraser_search_map_cache(slot_no, bucket, w->rd);
    if (!c) {
        c = eraser_cache_map(slot_no, bucket, w->rd);
    }

    /* Refresh the inode map key & IV. */
    eraser_refresh_map_entry(
        &c->map[eraser_get_inode_offset(w->inode_no)],
        w->rd
    );
    c->status |= ERASER_CACHE_DIRTY;
    c->last_dirty = jiffies;
    c->last_access = jiffies;

    /* Refresh the slot map key & IV as well. */
    eraser_refresh_map_entry(&w->rd->slot_map[slot_no], w->rd);
    set_bit(ERASER_KEY_SLOT_MAP_DIRTY, &w->rd->master_key_status);

    up(&w->rd->cache_lock[bucket]);

    eraser_free_unlink_work(w);
}

static void eraser_queue_unlink(struct eraser_unlink_work *w) {
    INIT_WORK(&w->work, eraser_do_unlink);
    queue_work(w->rd->unlink_queue, &w->work);
}

/* kprobe for vfs_unlink. */
static int eraser_unlink_kprobe_entry(struct kprobe *p, struct pt_regs *regs) {
    struct eraser_dev *rd;
    struct eraser_unlink_work *w;
    struct inode *dir = (struct inode *)regs->di;
    struct dentry *victim = (struct dentry *)regs->si;

    struct inode *inode = d_backing_inode(victim);

    // EUGEBE: This feels absolutely criminal/violation of abstractions, but
    // whatever, I really need this mnt_idmap lol. Not sure if it's correct though.
    struct mnt_idmap *dir_idmap = dir->i_sb->s_bdev_file->f_path.mnt->mnt_idmap;

    /* Perform all permission checks first, maybe we cannot delete. */
    if (d_is_negative(victim)
        || (!inode || !inode->i_sb || !inode->i_sb->s_bdev)
        || victim->d_parent->d_inode != dir
        || inode_permission(dir_idmap, dir, MAY_WRITE | MAY_EXEC)
        || IS_APPEND(dir)
        || (check_sticky(dir_idmap, dir, inode) || IS_APPEND(inode)
            || IS_IMMUTABLE(inode) || IS_SWAPFILE(inode))
        || d_is_dir(victim) || IS_DEADDIR(dir))
        goto nope;

    /* Queue an unlink work for the proper ERASER instance. */
    list_for_each_entry(rd, &eraser_dev_list, list) {
        if (rd->virt_dev == inode->i_sb->s_bdev->bd_dev) {
            w = eraser_allocate_unlink_work(inode->i_ino, rd);
            eraser_queue_unlink(w);
            break;
        }
    }

nope: /* Cannot unlink this inode. */
    return 0;
}

static struct kprobe eraser_unlink_kprobe = {
    .symbol_name = "vfs_unlink",
    .pre_handler = eraser_unlink_kprobe_entry,
};

/*
 * DM mapping function. This executes under make_generic_request(), and under
 * that function submit_bio() does not actually submit anything until we
 * return. This makes synchronous I/O impossible in this function, and we need
 * to do it for key retrieval. Therefore here we only set up a bottom half to do
 * the actual job later.
 */
static int eraser_map_bio(struct dm_target *ti, struct bio *bio) {
    struct bio *clone;
    struct eraser_io_work *w;
    struct eraser_dev *rd = (struct eraser_dev *)ti->private;

    if (unlikely(!rd->virt_dev))
        rd->virt_dev = bio->bi_bdev->bd_dev;

    // EUGEBE: bio_set_dev() seems like the way to properly do this now.
    // bio->bi_bdev = rd->real_dev->bdev;
    bio_set_dev(bio, rd->real_dev->bdev);

    bio->bi_iter.bi_sector =
        bio->bi_iter.bi_sector + (rd->rh->data_start * ERASER_SECTOR_SCALE);

    // EUGEBE: bi_rw is now bi_opf, and there is a dedicated bio_op() macro.
    if (unlikely(
            bio_op(bio) == REQ_OP_FLUSH || bio_op(bio) == REQ_OP_DISCARD
        )) {
        return DM_MAPIO_REMAPPED;
    }

    if (bio_has_data(bio)) {
        /* if (unlikely(bio->bi_iter.bi_size % ERASER_SECTOR != 0)) { */
        /* 	DMCRIT("WARNING: Incorrect IO size! Something's terribly wrong!"); */
        /* 	DMCRIT("remapping... sector: %lu, size: %u", bio->bi_iter.bi_sector,
     * bio->bi_iter.bi_size); */
        /* } */

        w = eraser_allocate_io_work(bio, rd);

        /* Perform a few NULL pointer checks, these things do happen
     * when bio is not a read/write operation. */
        /* If this is file I/O... */
        if (bio_iter_iovec(bio, bio->bi_iter).bv_page
            && bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping
            && bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping->host
            && S_ISREG(
                bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping->host->i_mode
            )) {
            w->is_file = 1; /* We will perform file encryption. */
        } else {
            w->is_file =
                0; /* We will perform good old disk sector encryption. */
        }

        /* We need to perform I/O to read keys, so send to bottom half. */
        if (bio_data_dir(bio) == WRITE) {
            bio_get(bio);
            eraser_queue_io(w);
            return DM_MAPIO_SUBMITTED;
        } else if (bio_data_dir(bio) == READ) {
            /* First submit the original I/O so that the read
       * operation is performed. We will catch completion in a
       * callback and do the decryption. */
            bio_get(bio);
            // clone = bio_clone_fast(bio, GFP_NOIO, rd->bioset);
            clone = bio_alloc_clone(bio->bi_bdev, bio, GFP_NOIO, rd->bioset);
            clone->bi_private = w;
            clone->bi_end_io = &eraser_read_end_io;
            submit_bio(clone);
            return DM_MAPIO_SUBMITTED;
        }
    }

    /* Remap everything else. */
    return DM_MAPIO_REMAPPED;
}

/*
 * Initializers, constructors & destructors.
 */

/* Initializes the AES-CTR context. */
static int eraser_init_rand_context(struct eraser_rand_context *rand) {
    u8 ctr[16];

    rand->buf = NULL;

    rand->tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(rand->tfm))
        return ERASER_ERROR;
    /* Key will be set later when filling the buffer. */

    /* Set random counter. */
    eraser_get_random_bytes_kernel(ctr, 16);
    // EUGEBE: TODO: See where this goes
    // crypto_blkcipher_set_iv(rand->tfm, ctr, 16);

    rand->max_byte =
        ERASER_PRNG_AESCTR_REFRESH_LEN / ERASER_PRNG_AESCTR_CHUNK_LEN;
    rand->max_chunk = ERASER_PRNG_AESCTR_CHUNK_LEN;

    rand->buf = kmalloc(rand->max_byte, GFP_KERNEL);
    while (!rand->buf) {
        DMCRIT(
            "Cannot allocate memory for AES-CTR, %llu bytes",
            rand->max_byte
        );

        if (rand->max_byte <= PAGE_SIZE) {
            DMCRIT("Bailing out");
            crypto_free_skcipher(rand->tfm);
            rand->tfm = NULL;
            return ERASER_ERROR;
        }

        rand->max_byte = rand->max_byte << 2;
        rand->max_chunk = rand->max_chunk >> 2;

        DMCRIT("Increasing chunks to: %llu", rand->max_chunk);

        rand->buf = kmalloc(rand->max_byte, GFP_KERNEL);
    }

    /* Initialize to invalid values. */
    rand->cur_byte = rand->max_byte;
    rand->cur_chunk = rand->max_chunk;

    return ERASER_SUCCESS;
}

static void eraser_destroy_rand_context(struct eraser_rand_context *rand) {
    if (rand->tfm)
        crypto_free_skcipher(rand->tfm);

    kfree(rand->buf);
}

/* Compute the ESSIV salt from sector encryption key. */
static int eraser_get_essiv_salt(u8 *key, u8 *salt) {
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int r;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return ERASER_ERROR;

    desc = kmalloc(
        sizeof(struct shash_desc) + crypto_shash_descsize(tfm),
        GFP_KERNEL
    );
    desc->tfm = tfm;
    // desc->flags = 0;

    r = crypto_shash_digest(desc, key, ERASER_KEY_LEN, salt);
    crypto_free_shash(tfm);
    kfree(desc);

    if (r == 0)
        return ERASER_SUCCESS;

    return ERASER_ERROR;
}

/*
 * Netlink communication for syncing the master key.
 *
 * Ideally, we would use Generic Netlink, but I'll be damned if the user space
 * library works correctly. Under they document it better, we fall back to
 * old-school netlink.
 */

/* /\* Command handlers. *\/ */
/* static int eraser_netlink_set_key(struct sk_buff *skb, struct genl_info
 * *info) */
/* { */
/* 	DMCRIT("SET KEY RECEIVED"); */
/* 	return 0; */
/* } */

/* static int eraser_netlink_get_key(struct sk_buff *skb, struct genl_info
 * *info) */
/* { */
/* 	DMCRIT("GET KEY RECEIVED"); */
/* 	return 0; */
/* } */

/* /\* Attributes. *\/ */
/* enum { */
/* 	ERASER_ATTR_UNSPEC, */
/* 	ERASER_ATTR_NAME, */
/* 	ERASER_ATTR_KEY, */
/* 	__ERASER_ATTR_MAX, */
/* }; */
/* #define	ERASER_ATTR_MAX (__ERASER_ATTR_MAX - 1) */

/* /\* Attribute policies. *\/ */
/* static struct nla_policy eraser_genl_policy[ERASER_ATTR_MAX + 1] = { */
/* 	[ERASER_ATTR_NAME] = {.type = NLA_NUL_STRING}, */
/* 	[ERASER_ATTR_KEY] = {.type = NLA_BINARY, .len = 32}, */
/* }; */

/* /\* Commands. *\/ */
/* enum { */
/* 	ERASER_CMD_GET_KEY, */
/* 	ERASER_CMD_SET_KEY, */
/* 	__ERASER_CMD_MAX, */
/* }; */
/* #define ERASER_CMD_MAX (__ERASER_CMD_MAX - 1) */

/* /\* Ops. *\/ */
/* static struct genl_ops eraser_genl_ops[ERASER_CMD_MAX + 1] = { */
/* 	[ERASER_CMD_GET_KEY] = { */
/* 		.cmd = ERASER_CMD_GET_KEY, */
/* 		.flags = 0, */
/* 		.policy = eraser_genl_policy, */
/* 		.doit = eraser_netlink_get_key, */
/* 		.dumpit = NULL, */
/* 	}, */

/* 	[ERASER_CMD_SET_KEY] = { */
/* 		.cmd = ERASER_CMD_SET_KEY, */
/* 		.flags = 0, */
/* 		.policy = eraser_genl_policy, */
/* 		.doit = eraser_netlink_set_key, */
/* 		.dumpit = NULL, */
/* 	}, */
/* }; */

/* /\* Netlink family. *\/ */
/* static struct genl_family eraser_genl_family = { */
/* 	.id = GENL_ID_GENERATE, */
/* 	.hdrsize = 0, */
/* 	.name = "ERASER", */
/* 	.version = 1, */
/* 	.maxattr = ERASER_ATTR_MAX, */
/* }; */

#define ERASER_NETLINK 31
#define ERASER_MSG_PAYLOAD (ERASER_NAME_LEN + ERASER_KEY_LEN)

enum {
    ERASER_MSG_GET_KEY,
    ERASER_MSG_SET_KEY,
    ERASER_MSG_DIE,
};

static struct sock *eraser_sock;

/* Rather, we ask it to die nicely. */
static int eraser_kill_helper(struct eraser_dev *rd) {
    struct nlmsghdr *h;
    struct sk_buff *skb_out;

    skb_out = nlmsg_new(0, GFP_KERNEL);
    if (!skb_out)
        DMCRIT("Cannot allocate sk_buff.");

    h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_DIE, 0, GFP_KERNEL);
    if (!h)
        DMCRIT("Cannot put msg.");

    NETLINK_CB(skb_out).dst_group = 0;

    /* Send! */
    if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
        DMCRIT("Error sending DIE.");
        return ERASER_ERROR;
    }

    return ERASER_SUCCESS;
}

/* Request the master key. */
static int eraser_get_master_key(struct eraser_dev *rd) {
    struct nlmsghdr *h;
    struct sk_buff *skb_out;
    unsigned char *payload;

    skb_out = nlmsg_new(ERASER_MSG_PAYLOAD, GFP_KERNEL);
    if (!skb_out)
        DMCRIT("Cannot allocate sk_buff.");

    h = nlmsg_put(
        skb_out,
        0,
        0,
        ERASER_MSG_GET_KEY,
        ERASER_MSG_PAYLOAD,
        GFP_KERNEL
    );
    if (!h)
        DMCRIT("Cannot put msg.");

    NETLINK_CB(skb_out).dst_group = 0;

    payload = nlmsg_data(h);
    memset(payload, 0, ERASER_MSG_PAYLOAD);
    memcpy(payload, rd->eraser_name, ERASER_NAME_LEN);

    /* Send! */
    if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
        DMCRIT("Error sending GET KEY.");
        return ERASER_ERROR;
    }

    return ERASER_SUCCESS;
}

/* Sync a new master key. */
static int eraser_set_master_key(struct eraser_dev *rd) {
    struct nlmsghdr *h;
    struct sk_buff *skb_out;
    unsigned char *payload;
    struct page *key_page;
    char *key_buf;
    u8 iv[ERASER_IV_LEN];

    skb_out = nlmsg_new(ERASER_MSG_PAYLOAD, GFP_KERNEL);
    if (!skb_out)
        DMCRIT("Cannot allocate sk_buff.");

    h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_SET_KEY, ERASER_MSG_PAYLOAD, 0);
    if (!h)
        DMCRIT("Cannot put msg.");

    NETLINK_CB(skb_out).dst_group = 0;

    payload = nlmsg_data(h);
    memset(payload, 0, ERASER_MSG_PAYLOAD);
    memcpy(payload, rd->eraser_name, ERASER_NAME_LEN);

    memset(iv, 0, ERASER_IV_LEN);

    key_page = eraser_allocate_page(rd);
    key_buf = kmap(key_page);
    memcpy(key_buf, rd->new_master_key, ERASER_KEY_LEN);
    eraser_do_crypto_from_page(
        key_page,
        0,
        ERASER_KEY_LEN,
        rd->enc_key,
        iv,
        NULL,
        ERASER_ENCRYPT,
        rd
    );
    memcpy(payload + ERASER_NAME_LEN, key_buf, ERASER_KEY_LEN);
    kunmap(key_page);
    eraser_free_page(key_page, rd);

    /* Send! */
    if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
        DMCRIT("Error sending SET KEY.");
        return ERASER_ERROR;
    }

    return ERASER_SUCCESS;
}

/* Netlink message receive callback. */
static void eraser_netlink_recv(struct sk_buff *skb_in) {
    struct eraser_dev *rd;
    struct nlmsghdr *h;
    unsigned char *payload;
    int len;
    u8 name[ERASER_NAME_LEN + 1];
    int found;
    struct page *key_page;
    char *key_buf;
    u8 iv[ERASER_IV_LEN];

    h = (struct nlmsghdr *)skb_in->data;
    payload = nlmsg_data(h);
    len = nlmsg_len(h);

    if (len != ERASER_MSG_PAYLOAD) {
        DMCRIT("Unknown message format.");
        return;
    }

    memcpy(name, payload, ERASER_NAME_LEN);
    name[ERASER_NAME_LEN] = '\0';

    found = 0;
    down(&eraser_dev_lock);
    list_for_each_entry(rd, &eraser_dev_list, list) {
        if (strcmp(rd->eraser_name, name) == 0) {
            found = 1;
            break;
        }
    }
    up(&eraser_dev_lock);

    if (!found) {
        DMCRIT("Message to unknown device.");
        return;
    }

    /* Now rd holds our device. */
    if (h->nlmsg_type == ERASER_MSG_GET_KEY) {
        /* We got the master key. */
        DMCRIT("Received master key.");
        if (test_and_clear_bit(
                ERASER_KEY_GET_REQUESTED,
                &rd->master_key_status
            )) {
            memset(iv, 0, ERASER_IV_LEN);

            key_page = eraser_allocate_page(rd);
            key_buf = kmap(key_page);
            memcpy(key_buf, payload + ERASER_NAME_LEN, ERASER_KEY_LEN);
            eraser_do_crypto_from_page(
                key_page,
                0,
                ERASER_KEY_LEN,
                rd->enc_key,
                iv,
                NULL,
                ERASER_DECRYPT,
                rd
            );
            memcpy(rd->master_key, key_buf, ERASER_KEY_LEN);
            kunmap(key_page);
            eraser_free_page(key_page, rd);

            set_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status);
            complete(&rd->master_key_wait);
        } else {
            DMCRIT("Received unsolicited key. Dropping.");
        }
    } else if (h->nlmsg_type == ERASER_MSG_SET_KEY) {
        /* We got confirmation that master key is synched to the vault. */
        DMCRIT("Received key sync ACK.");
        if (test_and_clear_bit(
                ERASER_KEY_SET_REQUESTED,
                &rd->master_key_status
            )) {
            set_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status);
            complete(&rd->master_key_wait);
        } else {
            DMCRIT("Received unsolicited ACK. Dropping.");
        }
    } else {
        DMCRIT("Unknown message type.");
    }

    /* TODO: Do *we* free the sk_buff here? Somebody please document netlink
   * properly! */
}

static struct netlink_kernel_cfg eraser_netlink_cfg = {
    .input = eraser_netlink_recv,
    .groups = 0,
    .flags = 0,
    // .cb_mutex = NULL,
    .bind = NULL,
};

/*
 * Constructor.
 */
static int eraser_ctr(struct dm_target *ti, unsigned int argc, char **argv) {
    struct eraser_dev *rd;
    int helper_pid;
    char dummy;
    int i;
    u8 salt[ERASER_KEY_LEN];
    int ret;

    /*
   * argv[0]: real block device path
   * argv[1]: eraser name, NOT path
   * argv[2]: hex key
   * argv[3]: virtual device path
   * argv[4]: helper pid
   */
    if (argc != 5) {
        ti->error = "Invalid argument count.";
        return -EINVAL;
    }

    DMCRIT("Creating ERASER on %s", argv[0]);

    if (sscanf(argv[4], "%d%c", &helper_pid, &dummy) != 1) {
        ti->error = "Invalid arguments.";
        return -EINVAL;
    }
    DMCRIT("Helper PID: %d", helper_pid);

    /* Lock everything until we make sure this device is create-able. */
    down(&eraser_dev_lock);

    rd = eraser_lookup_dev(argv[0]);
    if (rd) {
        ti->error = "ERASER already running on device.";
        goto lookup_dev_fail;
    }

    rd = eraser_create_dev(ti, argv[0], argv[1]);
    if (!rd) {
        ti->error = "Cannot create ERASER on device.";
        goto create_dev_fail;
    }
    up(&eraser_dev_lock);

    rd->helper_pid = helper_pid;

    /* Create memory pools, work queues, locks... */
    // EUGEBE: bioset_create() replaced with bioset_init()
    // rd->bioset = bioset_create(ERASER_BIOSET_SIZE, 0);
    ret = bioset_init(rd->bioset, ERASER_BIOSET_SIZE, 0, BIOSET_NEED_BVECS);
    if (ret != 0) {
        ti->error = "Could not create bioset.";
        goto create_bioset_fail;
    }

    rd->page_pool = mempool_create_page_pool(ERASER_PAGE_POOL_SIZE, 0);
    if (!rd->page_pool) {
        ti->error = "Could not create page pool.";
        goto create_page_pool_fail;
    }

    /* Read header from disk. */
    rd->rh = eraser_read_header(rd);
    if (!rd->rh) {
        ti->error = "Could not read header.";
        goto read_header_fail;
    }

    /* We have per-cpu crypto transforms. */
    rd->cpus = num_online_cpus();

    rd->rand =
        kmalloc(rd->cpus * sizeof(struct eraser_rand_context), GFP_KERNEL);
    for (i = 0; i < rd->cpus; ++i) {
        if (eraser_init_rand_context(&rd->rand[i]) == ERASER_ERROR) {
            ti->error = "Could not create random context.";
            goto init_rand_context_fail;
        }
    }

    /* Decode disk encryption key. */
    rd->enc_key = eraser_hex_decode(argv[2]);
    /* We don't need the key argument anymore, wipe it clean. */
    memset(argv[2], 0, strlen(argv[2]));

    rd->tfm = kmalloc(rd->cpus * sizeof(struct crypto_blkcipher *), GFP_KERNEL);
    for (i = 0; i < rd->cpus; ++i) {
        rd->tfm[i] = crypto_alloc_skcipher("cbc(aes)", 0, 0);
        if (IS_ERR(rd->tfm[i])) {
            ti->error = "Could not create crypto transform.";
            goto init_tfm_fail;
        }
    }

    rd->pprf_tfm =
        kmalloc(rd->cpus * sizeof(struct crypto_blkcipher *), GFP_KERNEL);
    for (i = 0; i < rd->cpus; ++i) {
        rd->pprf_tfm[i] = crypto_alloc_skcipher("ecb(aes)", 0, 0);
        if (IS_ERR(rd->pprf_tfm[i])) {
            ti->error = "Could not create crypto transform for pprf.";
            goto init_pprf_tfm_fail;
        }
    }

    /* ESSIV crypto transforms. */
    if (eraser_get_essiv_salt(rd->enc_key, salt) != ERASER_SUCCESS) {
        DMCRIT("SALT FAIL");
        ti->error = "Could not compute essiv salt.";
        goto compute_essiv_salt_fail;
    }

    rd->essiv_tfm =
        kmalloc(rd->cpus * sizeof(struct crypto_cipher *), GFP_KERNEL);
    for (i = 0; i < rd->cpus; ++i) {
        rd->essiv_tfm[i] = crypto_alloc_cipher("aes", 0, 0);
        if (IS_ERR(rd->essiv_tfm[i])) {
            ti->error = "Could not create essiv crypto transform.";
            goto init_essiv_fail;
        }
        crypto_cipher_setkey(rd->essiv_tfm[i], salt, ERASER_KEY_LEN);
    }

    /* Work caches and queues. */
    rd->_io_work_pool = KMEM_CACHE(eraser_io_work, 0);
    if (!rd->_io_work_pool) {
        ti->error = "Could not create io cache.";
        goto create_io_cache_fail;
    }

    rd->io_work_pool =
        mempool_create_slab_pool(ERASER_IO_WORK_POOL_SIZE, rd->_io_work_pool);
    if (!rd->io_work_pool) {
        ti->error = "Could not create io pool.";
        goto create_io_pool_fail;
    }

    rd->io_queue = create_workqueue("eraser_io");
    if (!rd->io_queue) {
        ti->error = "Could not create io queue.";
        goto create_io_queue_fail;
    }

    rd->_unlink_work_pool = KMEM_CACHE(eraser_unlink_work, 0);
    if (!rd->_unlink_work_pool) {
        ti->error = "Could not create unlink cache.";
        goto create_unlink_cache_fail;
    }

    rd->unlink_work_pool = mempool_create_slab_pool(
        ERASER_UNLINK_WORK_POOL_SIZE,
        rd->_unlink_work_pool
    );
    if (!rd->unlink_work_pool) {
        ti->error = "Could not create unlink pool.";
        goto create_unlink_pool_fail;
    }

    rd->unlink_queue = create_workqueue("eraser_unlink");
    if (!rd->unlink_queue) {
        ti->error = "Could not create unlink queue.";
        goto create_unlink_queue_fail;
    }

    rd->_map_cache_pool = KMEM_CACHE(eraser_map_cache, 0);
    if (!rd->_map_cache_pool) {
        ti->error = "Could not create map cache.";
        goto create_map_cache_cache_fail;
    }

    rd->map_cache_pool = mempool_create_slab_pool(
        ERASER_MAP_CACHE_POOL_SIZE,
        rd->_map_cache_pool
    );
    if (!rd->map_cache_pool) {
        ti->error = "Could not create map cache pool.";
        goto create_map_cache_pool_fail;
    }

    for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
        INIT_LIST_HEAD(&rd->map_cache_list[i]);
        sema_init(&rd->cache_lock[i], 1);
    }

    rd->map_cache_count = 0;

    /* Time to get the master key. */
    init_completion(&rd->master_key_wait);
    rd->master_key_status = 0;
    __set_bit(ERASER_KEY_GET_REQUESTED, &rd->master_key_status);
    while (eraser_get_master_key(rd) != ERASER_SUCCESS) {
        DMCRIT("Cannot send GET master key. Will retry.");
        msleep(3000);
    }
    while (!test_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status)) {
        DMCRIT("Waiting for master key.");
        wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
    }

    /* Read slot map from disk. */
    rd->slot_map = eraser_read_slot_map(
        rd->rh->slot_map_start,
        rd->rh->slot_map_len,
        rd->master_key,
        rd->rh->slot_map_iv,
        rd
    );
    if (!rd->slot_map) {
        ti->error = "Could not read slot map.";
        goto read_slot_map_fail;
    }

    rd->evict_map_cache_thread =
        kthread_run(&eraser_evict_map_cache, rd, "eraser_evict");
    if (IS_ERR(rd->evict_map_cache_thread)) {
        ti->error = "Could not create cache evict thread.";
        goto create_evict_thread_fail;
    }

    rd->real_dev_path = kmalloc(strlen(argv[0]) + 1, GFP_KERNEL);
    strcpy(rd->real_dev_path, argv[0]);
    rd->virt_dev_path = kmalloc(strlen(argv[3]) + 1, GFP_KERNEL);
    strcpy(rd->virt_dev_path, argv[3]);

    ti->num_discard_bios = 1;
    ti->private = rd;

    DMCRIT("Success.");
    return 0;

    /* Lots to clean up after an error. */
create_evict_thread_fail:
    vfree(rd->slot_map);
read_slot_map_fail:
    mempool_destroy(rd->map_cache_pool);
create_map_cache_pool_fail:
    kmem_cache_destroy(rd->_map_cache_pool);
create_map_cache_cache_fail:
    destroy_workqueue(rd->unlink_queue);
create_unlink_queue_fail:
    mempool_destroy(rd->unlink_work_pool);
create_unlink_pool_fail:
    kmem_cache_destroy(rd->_unlink_work_pool);
create_unlink_cache_fail:
    destroy_workqueue(rd->io_queue);
create_io_queue_fail:
    mempool_destroy(rd->io_work_pool);
create_io_pool_fail:
    kmem_cache_destroy(rd->_io_work_pool);
create_io_cache_fail:
    i = rd->cpus;
init_essiv_fail:
    /* We may have created some of the essiv contexts. */
    for (i = i - 1; i >= 0; --i)
        crypto_free_cipher(rd->essiv_tfm[i]);
    kfree(rd->essiv_tfm);

    i = rd->cpus;
compute_essiv_salt_fail: /* Fall through. */
init_pprf_tfm_fail:
    /* We may have created some of the pprf tfms. */
    for (i = i - 1; i >= 0; --i)
        crypto_free_skcipher(rd->pprf_tfm[i]);
    kfree(rd->pprf_tfm);

    i = rd->cpus;
init_tfm_fail:
    /* We may have created some of the tfms. */
    for (i = i - 1; i >= 0; --i)
        crypto_free_skcipher(rd->tfm[i]);
    kfree(rd->tfm);

    i = rd->cpus;
init_rand_context_fail:
    /* We may have created some of the random contexts. */
    for (i = i - 1; i >= 0; --i)
        eraser_destroy_rand_context(&rd->rand[i]);
    kfree(rd->rand);

    eraser_free_sector(rd->rh, rd);
read_header_fail:
    mempool_destroy(rd->page_pool);
create_page_pool_fail:
    bioset_exit(rd->bioset);
create_bioset_fail:
    down(&eraser_dev_lock);
    eraser_destroy_dev(ti, rd);
    up(&eraser_dev_lock);
create_dev_fail:
    /* Nothing. */
lookup_dev_fail:
    memset(argv[2], 0, strlen(argv[2])); /* Wipe key argument. */

    return -EINVAL;
}

/*
 * Destructor.
 */
static void eraser_dtr(struct dm_target *ti) {
    struct eraser_dev *rd = (struct eraser_dev *)ti->private;
    unsigned i;

    DMCRIT("Destroying.");

    kfree(rd->real_dev_path);
    kfree(rd->virt_dev_path);

    /* Stop auto eviction and write back cached maps. */
    kthread_stop(rd->evict_map_cache_thread);

    eraser_force_evict_map_cache(rd);

    /* Push master key! */ /* TODO: Add the simple logic to delay key sync
                          * here. Just use old key, set a flag in the
                          * header. */
    if (test_bit(ERASER_KEY_SLOT_MAP_DIRTY, &rd->master_key_status)) {
        eraser_get_random_key(rd->new_master_key, rd);
        __set_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status);
        while (eraser_set_master_key(rd) != ERASER_SUCCESS) {
            DMCRIT("Cannot send SET master key. Will retry.");
            msleep(3000);
        }

        while (!test_and_clear_bit(
            ERASER_KEY_READY_TO_REFRESH,
            &rd->master_key_status
        )) {
            DMCRIT("Waiting for new key to be set.");
            wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
        }
        DMCRIT("New key set.");
        memcpy(rd->master_key, rd->new_master_key, ERASER_KEY_LEN);
    }
    eraser_kill_helper(rd);

    /* Write back slot map. New master key was made ready above. */
    if (__test_and_clear_bit(
            ERASER_KEY_SLOT_MAP_DIRTY,
            &rd->master_key_status
        )) {
        DMCRIT("Writing slot map");
        eraser_get_random_iv(rd->rh->slot_map_iv, rd);
        eraser_write_slot_map(
            rd->slot_map,
            rd->rh->slot_map_start,
            rd->rh->slot_map_len,
            rd->master_key,
            rd->rh->slot_map_iv,
            rd
        );
    }
    vfree(rd->slot_map);

    /* Keys no longer needed, wipe them. */
    memset(rd->new_master_key, 0, ERASER_KEY_LEN);
    memset(rd->master_key, 0, ERASER_KEY_LEN);
    memset(rd->enc_key, 0, ERASER_KEY_LEN);

    /* Write header. */
    eraser_write_header(rd->rh, rd);
    eraser_free_sector(rd->rh, rd);

    /* Clean up. */
    mempool_destroy(rd->map_cache_pool);
    kmem_cache_destroy(rd->_map_cache_pool);

    destroy_workqueue(rd->unlink_queue);
    mempool_destroy(rd->unlink_work_pool);
    kmem_cache_destroy(rd->_unlink_work_pool);

    destroy_workqueue(rd->io_queue);
    mempool_destroy(rd->io_work_pool);
    kmem_cache_destroy(rd->_io_work_pool);

    for (i = 0; i < rd->cpus; ++i)
        crypto_free_cipher(rd->essiv_tfm[i]);

    kfree(rd->essiv_tfm);

    for (i = 0; i < rd->cpus; ++i)
        crypto_free_skcipher(rd->tfm[i]);

    kfree(rd->tfm);

    for (i = 0; i < rd->cpus; ++i)
        eraser_destroy_rand_context(&rd->rand[i]);

    kfree(rd->rand);

    mempool_destroy(rd->page_pool);
    // bioset_free(rd->bioset);
    bioset_exit(rd->bioset);

    down(&eraser_dev_lock);
    eraser_destroy_dev(ti, rd);
    up(&eraser_dev_lock);

    DMCRIT("Success.");
}

static void eraser_io_hints(struct dm_target *ti, struct queue_limits *limits) {
    limits->logical_block_size = ERASER_SECTOR;
    limits->physical_block_size = ERASER_SECTOR;
    limits->io_min = ERASER_SECTOR;
    limits->io_opt = ERASER_SECTOR;
}

static struct target_type eraser_target = {
    .name = "eraser",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = eraser_ctr,
    .dtr = eraser_dtr,
    .map = eraser_map_bio,
    /* .status = eraser_status, */
    /* .ioctl  = eraser_ioctl, */
    .io_hints = eraser_io_hints,
};

/* Module entry. */
static int __init dm_eraser_init(void) {
    int r;

    eraser_sock =
        netlink_kernel_create(&init_net, ERASER_NETLINK, &eraser_netlink_cfg);
    if (!eraser_sock) {
        DMERR("Netlink setup failed.");
        return -1;
    }

    r = register_kprobe(&eraser_unlink_kprobe);
    if (r < 0) {
        DMERR("Register kprobe failed %d", r);
        return -1;
    }

    r = dm_register_target(&eraser_target);
    if (r < 0)
        DMERR("dm_register failed %d", r);

    if (!proc_create(ERASER_PROC_FILE, 0, NULL, &eraser_fops)) {
        DMERR("Cannot create proc file.");
        return -ENOMEM;
    }

    DMCRIT("ERASER loaded.");
    return r;
}

/* Module exit. */
static void __exit dm_eraser_exit(void) {
    remove_proc_entry(ERASER_PROC_FILE, NULL);
    dm_unregister_target(&eraser_target);
    unregister_kprobe(&eraser_unlink_kprobe);
    netlink_kernel_release(eraser_sock);
    DMCRIT("ERASER unloaded.");
}

module_init(dm_eraser_init);
module_exit(dm_eraser_exit);

MODULE_AUTHOR("Kaan Onarlioglu <http://www.onarlioglu.com>");
MODULE_DESCRIPTION(DM_NAME " target for ERASER.");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif
