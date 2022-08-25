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

#include "dm-holepunch-main.h"

/* Decodes a hex encoded byte string. */
static u8 *eraser_hex_decode(u8 *hex)
{
	u8 buf[3];
	u8 *s;
	unsigned len;
	unsigned i;

	buf[2] = '\0';
	len = strlen(hex) / 2;

	s = kmalloc(len, GFP_KERNEL);
	memset(s, 0, len);

	for (i = 0; i < len; ++i)
	{
		buf[0] = *hex++;
		buf[1] = *hex++;
		kstrtou8(buf, 16, &s[i]);
	}

	return s;
}

/*
 * /proc file functions.
 */

/* Iterates over all eraser_devs and prints the instance info. */
static int eraser_list_mounts(struct seq_file *f, void *v)
{
	struct eraser_dev *cur;

	down(&eraser_dev_lock);
	list_for_each_entry(cur, &eraser_dev_list, list)
	{
		seq_printf(f, "%s %s %s\n", cur->eraser_name, cur->real_dev_path, cur->virt_dev_path);
	}
	up(&eraser_dev_lock);

	return 0;
}

/* Open handler for the /proc file. */
static int eraser_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, eraser_list_mounts, NULL);
}

/* /proc file operations. */
static const struct file_operations eraser_fops = {
	.owner = THIS_MODULE,
	.open = eraser_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * Memory management.
 */

static struct page *eraser_allocate_page(struct eraser_dev *rd)
{
	struct page *p;

	p = mempool_alloc(rd->page_pool, GFP_KERNEL);
	if (!p)
		DMWARN("Cannot allocate new page!");

	return p;
}

static inline void eraser_free_page(struct page *p, struct eraser_dev *rd)
{
	mempool_free(p, rd->page_pool);
}

static void eraser_free_sector(void *s, struct eraser_dev *rd)
{
	struct page *p;

	p = virt_to_page(s);
	kunmap(p);
	mempool_free(p, rd->page_pool);
}

static struct bio *eraser_allocate_bio_multi_vector(int vec_no, struct eraser_dev *rd)
{
	struct bio *b;

	b = bio_alloc_bioset(GFP_KERNEL, vec_no, rd->bioset);
	if (!b)
		DMWARN("Cannot allocate new bio!");

	return b;
}

static inline struct bio *eraser_allocate_bio(struct eraser_dev *rd)
{
	return eraser_allocate_bio_multi_vector(1, rd);
}

static struct eraser_io_work *eraser_allocate_io_work(struct bio *bio, struct eraser_dev *rd)
{
	struct eraser_io_work *w;

	w = mempool_alloc(rd->io_work_pool, GFP_NOIO);
	if (!w) {
		DMWARN("Cannot allocate new io work!");
	} else {
		w->bio = bio;
		w->rd = rd;
	}
	return w;
}

static inline void eraser_free_io_work(struct eraser_io_work *w)
{
	mempool_free(w, w->rd->io_work_pool);
}

static struct eraser_unlink_work *eraser_allocate_unlink_work(unsigned long ino, struct eraser_dev *rd)
{
	struct eraser_unlink_work *w;

	w = mempool_alloc(rd->unlink_work_pool, GFP_ATOMIC);
	if (!w)	{
		DMWARN("Cannot allocate new unlink work!");
	} else {
		w->ino = ino;
		w->rd = rd;
	}
	return w;
}

static inline void eraser_free_unlink_work(struct eraser_unlink_work *w)
{
	mempool_free(w, w->rd->unlink_work_pool);
}

static struct eraser_map_cache *eraser_allocate_map_cache(struct eraser_dev *rd)
{
	struct eraser_map_cache *c;

	c = mempool_alloc(rd->map_cache_pool, GFP_NOIO);
	if (!c) {
		DMWARN("Cannot allocate new map cache!");
	} else {
		memset(c, 0, sizeof *c);
	}
	return c;
}

static inline void eraser_free_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd)
{
	mempool_free(c, rd->map_cache_pool);
}

/*
 * ERASER device management functions.
 */

/* Looks up a block device by path. */
static int __eraser_lookup_dev(char *dev_path, dev_t *dev)
{
	struct block_device *bdev;

	bdev = lookup_bdev(dev_path);
	if (IS_ERR(bdev))
		return ERASER_ERROR;

	*dev = bdev->bd_dev;
	bdput(bdev);

	return ERASER_SUCCESS;
}

/* Looks up a ERASER device by its underlying block device. */
static struct eraser_dev *eraser_lookup_dev(char *dev_path)
{
	struct eraser_dev *cur;
	dev_t dev;

	if (__eraser_lookup_dev(dev_path, &dev) == ERASER_ERROR) {
		DMERR("Device lookup failed!");
		return NULL;
	}

	list_for_each_entry(cur, &eraser_dev_list, list) {
		if (cur->real_dev->bdev->bd_dev == dev)
			return cur;
	}

	return NULL;
}

/* Creates a new ERASER device. */
static struct eraser_dev *eraser_create_dev(struct dm_target *ti, char *dev_path, char *name)
{
	struct eraser_dev *rd;

	rd = kmalloc(sizeof(*rd), GFP_KERNEL);
	memset(rd, 0, sizeof(*rd));
	memcpy(rd->eraser_name, name, ERASER_NAME_LEN);
	rd->eraser_name[ERASER_NAME_LEN] = '\0';

	if (dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &rd->real_dev))
	{
		kfree(rd);
		return NULL;
	}

	INIT_LIST_HEAD(&rd->list);
	list_add(&rd->list, &eraser_dev_list);

	return rd;
}

/* Destroys a ERASER device. */
static void eraser_destroy_dev(struct dm_target *ti, struct eraser_dev *rd)
{
	list_del(&rd->list);
	dm_put_device(ti, rd->real_dev);
	kfree(rd);
}

/*
 * Crypto functions.
 */

/*
 * The block cipher transform should already be initialized (with key and IV);
 * mostly a convenience function to avoid scatterlists.
 */
static void __holepunch_blkcipher(void *dst, void *src, u64 len, int op,
		struct crypto_blkcipher *tfm)
{
	struct scatterlist sg_src;
	struct scatterlist sg_dst;
	struct blkcipher_desc d;
	int r;

	sg_init_one(&sg_src, src, len);
	sg_init_one(&sg_dst, dst, len);

	d.tfm = tfm;
	d.flags = 0;

	if (op == ERASER_ENCRYPT) {
		r = crypto_blkcipher_encrypt(&d, &sg_dst, &sg_src, len);
		if (r)
			DMERR("Error encrypting: %d", r);
	} else if (op == ERASER_DECRYPT) {
		r = crypto_blkcipher_decrypt(&d, &sg_dst, &sg_src, len);
		if (r)
			DMERR("Error decrypting: %d", r);
	} else {
		DMERR("Invalid crypto operation");
	}
}

/* Do AES-ECB between two buffers, using the per-cpu transforms. */
static void holepunch_ecb(struct eraser_dev *rd, void *dst, void *src, u64 len,
		int op, u8 *key)
{
	struct crypto_blkcipher *tfm = rd->ecb_tfm[get_cpu()];
	crypto_blkcipher_setkey(tfm, key, ERASER_KEY_LEN);
	__holepunch_blkcipher(dst, src, len, op, tfm);
	put_cpu();
}

/* Do AES-CBC between two buffers, using the per-cpu transforms. */
static void holepunch_cbc(struct eraser_dev *rd, void *dst, void *src, u64 len,
		int op, u8 *key, u8 *iv)
{
	struct crypto_blkcipher *tfm = rd->cbc_tfm[get_cpu()];
	crypto_blkcipher_setkey(tfm, key, ERASER_KEY_LEN);
	crypto_blkcipher_set_iv(tfm, iv, ERASER_IV_LEN);
	__holepunch_blkcipher(dst, src, len, op, tfm);
	put_cpu();
}

/* Generate the IV for a sector. */
static void holepunch_gen_iv(struct eraser_dev *rd, u8 *iv, u64 sector)
{
	u8 input[ERASER_IV_LEN] = {0};
	*(u64 *) input = sector;
	holepunch_ecb(rd, iv, input, ERASER_IV_LEN, ERASER_ENCRYPT, rd->hp_h->iv_key);
}

/* Perform AES-CBC on a single sector. */
static void holepunch_cbc_sector(struct eraser_dev *rd, void *dst, void *src,
		int op, u8 *key, u64 sectorno)
{
	u8 iv[ERASER_IV_LEN] = {0};
	holepunch_gen_iv(rd, iv, sectorno);
	holepunch_cbc(rd, dst, src, ERASER_SECTOR, op, key, iv);
}

/* Perform AES-CBC in-place on a single sector. */
static inline void holepunch_cbc_sector_inplace(struct eraser_dev *rd,
		void* sector, int op, u8 *key, u64 sectorno)
{
	holepunch_cbc_sector(rd, sector, sector, op, key, sectorno);
}

/* Perform AES-CBC for a file key sector. */
static void holepunch_cbc_filekey_sector(struct eraser_dev *rd, void *dst,
		void *src, int op, u8 *key, u64 sectorno)
{
	u8 iv[ERASER_IV_LEN] = {0};
	holepunch_gen_iv(rd, iv, sectorno);
	/* Exclude the tag, but include the magic bytes. */
	holepunch_cbc(rd, dst + 16, src + 16, ERASER_SECTOR - 16, op, key, iv);
	/* Still copy the tag if to a different destination, though. */
	if (dst != src)
		memcpy(dst, src, 8);
}

/*
 * Create a PRG from AES-ECB for the PPRF; input assumed to be ERASER_KEY_LEN
 * and output assumed to be ERASER_KEY_LEN * 2.
 */
static inline void holepunch_prg(struct eraser_dev *rd, u8 *input, u8 *output)
{
	holepunch_ecb(rd, output, rd->prg_input, ERASER_KEY_LEN * 2, ERASER_ENCRYPT, input);
}

/* Needed for the type to keep the PPRF generic. */
void holepunch_prg_generic(void *v, u8 *input, u8 *output)
{
	holepunch_prg(v, input, output);
}

/* Calculate a sha256 hash; output expected to be HP_HASH_LEN. */
static void holepunch_hash(struct eraser_dev *rd, void *in, u64 len, void *out)
{
	SHASH_DESC_ON_STACK(d, rd->sha_tfm);
	d->tfm = rd->sha_tfm;
	d->flags = 0;
	if (crypto_shash_digest(d, in, len, out))
		DMERR("Error calculating hash digest");
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
static void *__eraser_rw_sector(struct block_device *bdev, u64 sector,
								int rw, void *write_buf, struct eraser_dev *rd)
{
	struct bio *bio;
	struct page *p;

	if (rw == WRITE && !write_buf) {
		DMWARN("Write buffer is NULL, aborting");
		return NULL;
	}

	bio = eraser_allocate_bio(rd);
	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = sector * ERASER_SECTOR_SCALE;

	if (rw == READ) {
		p = eraser_allocate_page(rd);
		bio->bi_rw &= ~REQ_WRITE;
	} else {
		p = virt_to_page(write_buf);
		bio->bi_rw |= REQ_WRITE;
	}

	bio_add_page(bio, p, ERASER_SECTOR, 0);

	submit_bio_wait(0, bio);

	bio_put(bio);

	return kmap(p);
}

/* Shortcut for I/O on the underlying block device. */
static inline void *eraser_rw_sector(u64 sector, int rw, void *write_buf, struct eraser_dev *rd)
{
	return __eraser_rw_sector(rd->real_dev->bdev, sector, rw, write_buf, rd);
}

// TODO improve these (see later note)
static void holepunch_write_header(struct eraser_dev *rd)
{
	eraser_rw_sector(0, WRITE, rd->hp_h, rd);
}

static void holepunch_read_header(struct eraser_dev *rd)
{
	rd->hp_h = eraser_rw_sector(0, READ, NULL, rd);
}

/*
 * PPRF & FKT basics.
 */

/* Return the key for a PPRF FKT bottom sector. */
static inline u8 *holepunch_fkt_bottom_key(struct eraser_dev *rd, u64 index)
{
	return rd->pprf_fkt[index / HP_FKT_PER_SECTOR]
		.entries[index % HP_FKT_PER_SECTOR].key;
}

/* Return the key for a PPRF keynode sector. */
static inline u8 *holepunch_pprf_key(struct eraser_dev *rd, u64 index)
{
	return rd->pprf_fkt[index / HP_FKT_PER_SECTOR + rd->hp_h->fkt_top_width]
		.entries[index % HP_FKT_PER_SECTOR].key;
}

static void holepunch_read_fkt(struct eraser_dev *rd)
{
	void *data;
	u64 s;
	for (s = 0; s != rd->hp_h->fkt_top_width; ++s) {
		data = eraser_rw_sector(rd->hp_h->fkt_start + s, READ, NULL, rd);
		holepunch_cbc_sector(rd, rd->pprf_fkt + s, data, ERASER_DECRYPT,
			rd->master_key, rd->hp_h->fkt_start + s);
		eraser_free_sector(data, rd);
	}
	for (; s != rd->fkt_len; ++s) {
		data = eraser_rw_sector(rd->hp_h->fkt_start + s, READ, NULL, rd);
		holepunch_cbc_sector(rd, rd->pprf_fkt + s, data, ERASER_DECRYPT,
			holepunch_fkt_bottom_key(rd, s - rd->hp_h->fkt_top_width),
			rd->hp_h->fkt_start + s);
		eraser_free_sector(data, rd);
	}
}

static void holepunch_read_pprf(struct eraser_dev *rd)
{
	void *data;
	u64 s;
	for (s = 0; s < DIV_ROUND_UP(rd->hp_h->pprf_size, HP_PPRF_PER_SECTOR); ++s) {
		data = eraser_rw_sector(rd->hp_h->pprf_start + s, READ, NULL, rd);
		holepunch_cbc_sector_inplace(rd, data, ERASER_DECRYPT,
			holepunch_pprf_key(rd, s), rd->hp_h->pprf_start + s);
		memcpy(rd->pprf_key + s * HP_PPRF_PER_SECTOR, data,
			sizeof(struct pprf_keynode) * HP_PPRF_PER_SECTOR);
		eraser_free_sector(data, rd);
	}
}

/* PPRF read lock outside. */
static int holepunch_evaluate_at_tag(struct eraser_dev *rd, u64 tag, u8 *out,
		struct pprf_keynode *pprf)
{
	++rd->stats_evaluate;
	return evaluate_at_tag(pprf, rd->hp_h->pprf_depth, holepunch_prg_generic,
		rd, tag, out);
}

/*
 * Journaling.
 */

/* Replay the journal. */
static void holepunch_journal_replay(struct eraser_dev *rd)
{
	void *blk;
	int i;
	for (i = 1; i < HP_JOURNAL_LEN; ++i) {
		if (rd->journal[i] == rd->hp_h->journal_start) break;
		// TODO doing this all sequentially seems very inefficient
		blk = eraser_rw_sector(rd->hp_h->journal_start + i, READ, NULL, rd);
		eraser_rw_sector(rd->journal[i], WRITE, blk, rd);
		eraser_free_sector(blk, rd);
	}
}

/* Commit the current journal transaction. */
static void holepunch_journal_commit(struct eraser_dev *rd)
{
	if (!rd->journal) return;
	if (rd->journal_entry < HP_JOURNAL_LEN)
		rd->journal[rd->journal_entry] = rd->hp_h->journal_start;
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, rd->journal, rd);
	holepunch_journal_replay(rd);
	rd->journal[0] = HPJ_NONE;
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, rd->journal, rd);
	eraser_free_sector(rd->journal, rd);
	rd->journal = NULL;
}

/*
 * Queue a write for the current journal transaction (making one if necessary);
 * overwrites previous writes to the same location. If the journal is full,
 * commits and starts over; if this behavior isn't desired, use
 * rd->journal_entry and holepunch_journal_commit manually.
 */
static void holepunch_journal_write(struct eraser_dev *rd, u64 addr, void *data)
{
	struct page *p;
	int i;
	if (rd->journal_entry == HP_JOURNAL_LEN)
		holepunch_journal_commit(rd);
	if (!rd->journal) {
		p = eraser_allocate_page(rd);
		rd->journal = kmap(p);
		rd->journal[0] = HPJ_GENERIC;
		rd->journal_entry = 1;
	}
	for (i = 1; i < rd->journal_entry; ++i) {
		if (rd->journal[i] == addr)
			break;
	}
	rd->journal[i] = addr;
	eraser_rw_sector(rd->hp_h->journal_start + i, WRITE, data, rd);
	rd->journal_entry++;
}

static void holepunch_tpm_set_master(struct eraser_dev *rd, u8 *new_key);

/* Perform the (post-journaling) steps necessary to rotate the master key. */
static void holepunch_do_master_rotation(struct eraser_dev *rd, void *new_key)
{
	u64 i;
	void *blk;
	for (i = 0; i < rd->hp_h->fkt_top_width; ++i) {
		// TODO again, this feels a little silly to allocate and free for each
		// block, and also to wait for each bio individually
		blk = eraser_rw_sector(rd->hp_h->journal_start + i + 1, READ, NULL, rd);
		eraser_rw_sector(rd->hp_h->fkt_start, WRITE, blk, rd);
		eraser_free_sector(blk, rd);
	}
	holepunch_tpm_set_master(rd, new_key);
}

/* Journal, then complete, a master key rotation. */
static void holepunch_rotate_master(struct eraser_dev *rd)
{
	struct page *p1, *p2;
	void *ctl, *blk;
	u64 i;
	u8 new_key[ERASER_KEY_LEN];
	kernel_random(new_key, ERASER_KEY_LEN);
	p1 = eraser_allocate_page(rd);
	p2 = eraser_allocate_page(rd);
	ctl = kmap(p1);
	blk = kmap(p2);
	*(u64 *) ctl = HPJ_MASTER_ROT;
	holepunch_ecb(rd, ctl + 8, new_key, ERASER_KEY_LEN, ERASER_ENCRYPT, rd->master_key);
	holepunch_hash(rd, rd->master_key, ERASER_KEY_LEN, ctl + 8 + ERASER_KEY_LEN);
	for (i = 0; i < rd->hp_h->fkt_top_width; ++i) {
		holepunch_cbc_sector(rd, blk, rd->pprf_fkt + i, ERASER_ENCRYPT, new_key,
			rd->hp_h->fkt_start + i);
		eraser_rw_sector(rd->hp_h->journal_start + i + 1, WRITE, blk, rd);
	}
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, ctl, rd);
	holepunch_do_master_rotation(rd, new_key);
	*(u64 *) ctl = HPJ_NONE;
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, ctl, rd);
	kunmap(p1);
	kunmap(p2);
	eraser_free_page(p1, rd);
	eraser_free_page(p2, rd);
}

/* Perform the (post-journaling) steps necessary to rotate the pprf key. */
static void holepunch_do_pprf_rotation(struct eraser_dev *rd, u8 *new_key,
	int ignore_magic)
{
	// TODO this could be more efficient with memoization, since it's all sequential
	struct pprf_keynode new;
	struct page *p;
	u64 s;
	struct holepunch_filekey_sector *cipher, *plain;
	u8 key[ERASER_KEY_LEN];
	p = eraser_allocate_page(rd);
	plain = kmap(p);
	new.flag = PPRF_KEYLEAF;
	memcpy(new.v.key, new_key, ERASER_KEY_LEN);
	/* Loop with new key until magic is wrong. */
	for (s = rd->hp_h->key_table_start; s != rd->hp_h->fkt_start; ++s) {
		cipher = eraser_rw_sector(s, READ, NULL, rd);
		holepunch_evaluate_at_tag(rd, cipher->tag, key, &new);
		holepunch_cbc_filekey_sector(rd, plain, cipher, ERASER_DECRYPT, key, s);
		eraser_free_sector(cipher, rd);
		if (unlikely(ignore_magic || plain->magic1 != HP_MAGIC1
			|| plain->magic2 != HP_MAGIC2))
			break;
	}
	/* Then switch to old and overwrite via new. */
	for (; s != rd->hp_h->fkt_start; ++s) {
		cipher = eraser_rw_sector(s, READ, NULL, rd);
		holepunch_evaluate_at_tag(rd, cipher->tag, key, rd->pprf_key);
		holepunch_cbc_filekey_sector(rd, plain, cipher, ERASER_DECRYPT, key, s);
		plain->tag = s - rd->hp_h->key_table_start;
		if (unlikely(ignore_magic || plain->magic1 != HP_MAGIC1
			|| plain->magic2 != HP_MAGIC2)) {
			if (unlikely(!ignore_magic))
				DMWARN("Bad magic bytes found and reset; inodes %llu-%llu may experience data loss",
					(s - rd->hp_h->key_table_start) * HP_KEY_PER_SECTOR,
					(s + 1 - rd->hp_h->key_table_start) * HP_KEY_PER_SECTOR - 1);
			plain->magic1 = HP_MAGIC1;
			plain->magic2 = HP_MAGIC2;
		}
		holepunch_evaluate_at_tag(rd, plain->tag, key, &new);
		holepunch_cbc_filekey_sector(rd, cipher, plain, ERASER_ENCRYPT, key, s);
		eraser_rw_sector(s, WRITE, cipher, rd);
		eraser_free_sector(cipher, rd);
	}
#ifdef HOLEPUNCH_DEBUG
	DMINFO("Done with key transition, moving to FKT.");
#endif
	/* Setup AES-CTR instance, then reset FKT. */
	kernel_random(key, ERASER_KEY_LEN);
	crypto_blkcipher_setkey(rd->ctr_tfm, key, ERASER_KEY_LEN);
	for (s = 0; s != rd->hp_h->fkt_top_width; ++s) {
		__holepunch_blkcipher(rd->pprf_fkt + s, rd->pprf_fkt + s, ERASER_SECTOR,
			ERASER_ENCRYPT, rd->ctr_tfm);
		eraser_rw_sector(rd->hp_h->fkt_start + s, WRITE, rd->pprf_fkt + s, rd);
		holepunch_cbc_sector_inplace(rd, rd->pprf_fkt + s, ERASER_DECRYPT,
			rd->master_key, rd->hp_h->fkt_start + s);
	}
	for (; s != rd->fkt_len; ++s) {
		__holepunch_blkcipher(rd->pprf_fkt + s, rd->pprf_fkt + s, ERASER_SECTOR,
			ERASER_ENCRYPT, rd->ctr_tfm);
		eraser_rw_sector(rd->hp_h->fkt_start + s, WRITE, rd->pprf_fkt + s, rd);
		holepunch_cbc_sector_inplace(rd, rd->pprf_fkt + s, ERASER_DECRYPT,
			holepunch_fkt_bottom_key(rd, s - rd->hp_h->fkt_top_width),
			rd->hp_h->fkt_start + s);
	}
	/* Write PPRF key, its size, and the tag counter. */
	memset(rd->pprf_key, 0, ERASER_SECTOR);
	memcpy(rd->pprf_key, &new, sizeof(new));
	holepunch_cbc_sector(rd, plain, rd->pprf_key, ERASER_ENCRYPT,
		holepunch_pprf_key(rd, 0), rd->hp_h->pprf_start);
	eraser_rw_sector(rd->hp_h->pprf_start, WRITE, plain, rd);
	rd->hp_h->pprf_size = 1;
	rd->hp_h->tag_counter = rd->key_table_len;
	holepunch_write_header(rd);
	kunmap(p);
	eraser_free_page(p, rd);
}

/*
 * Journal, then complete, a pprf key rotation. Assumes the PPRF write lock is
 * held and the cache is empty.
 */
static void holepunch_rotate_pprf(struct eraser_dev *rd)
{
	struct page *p;
	u64 *ctl;
	u8 new_key[ERASER_KEY_LEN];
	kernel_random(new_key, ERASER_KEY_LEN);
	p = eraser_allocate_page(rd);
	ctl = kmap(p);
	/* PPRF rotation and journal clear. */
	ctl[0] = HPJ_PPRF_ROT;
	holepunch_ecb(rd, ctl + 1, new_key, ERASER_KEY_LEN, ERASER_ENCRYPT, rd->master_key);
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, ctl, rd);
	holepunch_do_pprf_rotation(rd, new_key, 0);
	ctl[0] = HPJ_NONE;
	eraser_rw_sector(rd->hp_h->journal_start, WRITE, ctl, rd);
	kunmap(p);
	eraser_free_page(p, rd);
	holepunch_rotate_master(rd);
}

/*
 * Cache management.
 */

/* Drop a cache entry. Bucket lock must be held. */
static inline void eraser_drop_map_cache(struct eraser_dev *rd, struct eraser_map_cache *c)
{
	list_del(&c->list);
	eraser_free_sector(c->map, rd);
	eraser_free_map_cache(c, rd);
	down_write(&rd->map_cache_count_sem);
	rd->map_cache_count -= 1;
	up_write(&rd->map_cache_count_sem);
}

static void holepunch_persist_unlink(struct eraser_dev *rd,
		struct eraser_map_cache *c, struct semaphore *cache_lock);

/*
 * Drops all cache entries, writing them back to disk if dirty. Takes each
 * bucket lock in turn, in addition to the PPRF lock (read or write depending
 * on puncture).
 */
static void eraser_force_evict_map_cache(struct eraser_dev *rd, int puncture)
{
	struct eraser_map_cache *c;
	struct eraser_map_cache *n;
	int i;
	u8 key[ERASER_KEY_LEN];

	for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
		down(&rd->cache_lock[i]);
		list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list) {
			if (c->status & ERASER_CACHE_DIRTY) {
				if (puncture) {
					holepunch_persist_unlink(rd, c, &rd->cache_lock[i]);
				} else {
					HP_DOWN_READ(&rd->pprf_sem, "evict cache");
					holepunch_evaluate_at_tag(rd, *(u64 *)c->map, key,
						rd->pprf_key);
					HP_UP_READ(&rd->pprf_sem, "evict cache");
					holepunch_cbc_filekey_sector(rd, c->map, c->map,
						ERASER_ENCRYPT, key, c->sector);
					eraser_rw_sector(c->sector, WRITE, c->map, rd);
				}
			}
			eraser_drop_map_cache(rd, c);
		}
		up(&rd->cache_lock[i]);
	}
	holepunch_journal_commit(rd);
}

/*
 * Searches the cache for the entry containing the key for this inode; if not
 * found, reads the sector from disk and caches it. Passes the relevant bucket
 * lock to the caller.
 */
static struct eraser_map_cache *holepunch_get_cache_entry(struct eraser_dev *rd,
		u64 ino, struct semaphore **cache_lock)
{
	struct eraser_map_cache *c;
	u64 sector, bucket;
	u8 key[ERASER_KEY_LEN]; /* If we need to read it */
	sector = ino / HP_KEY_PER_SECTOR;
	bucket = sector % ERASER_MAP_CACHE_BUCKETS;

	*cache_lock = &rd->cache_lock[bucket];
	HP_DOWN(*cache_lock, "Bucket %u get entry", bucket);

	/* Look first */
	list_for_each_entry(c, &rd->map_cache_list[bucket], list) {
		if (c->sector == sector) {
			c->last_access = jiffies;
			return c;
		}
	}

	/* If not found, read it... */
	c = eraser_allocate_map_cache(rd);
	c->map = eraser_rw_sector(rd->hp_h->key_table_start + sector, READ, NULL, rd);
	HP_DOWN_READ(&rd->pprf_sem, "PPRF: read sector");
	holepunch_evaluate_at_tag(rd, *(u64 *)c->map, key, rd->pprf_key);
	HP_UP_READ(&rd->pprf_sem, "PPRF: read sector");
	holepunch_cbc_filekey_sector(rd, c->map, c->map, ERASER_DECRYPT, key,
		rd->hp_h->key_table_start + sector);

	/* ...then add it to the cache */
	c->sector = sector;
	c->status = 0;
	c->first_access = jiffies;
	c->last_access = jiffies;
	INIT_LIST_HEAD(&c->list);
	list_add(&c->list, &rd->map_cache_list[bucket]);

	down_write(&rd->map_cache_count_sem);
	rd->map_cache_count += 1;
	up_write(&rd->map_cache_count_sem);

	return c;
}

static void holepunch_get_inode_key(struct eraser_dev *rd, u8 *dst, u64 ino)
{
	struct holepunch_filekey_sector *sector;
	struct semaphore *cache_lock;
	sector = holepunch_get_cache_entry(rd, ino, &cache_lock)->map;
	memcpy(dst, sector->entries[ino % HP_KEY_PER_SECTOR].key, ERASER_KEY_LEN);
	HP_UP(cache_lock, "inode %llu get key", inode_no);
}

/* Cache eviction runs in separate kernel thread, periodically. */
static int holepunch_evict_map_cache(void *data)
{
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
// #ifdef HOLEPUNCH_DEBUG
// 		KWORKERMSG("The reaper has awoken\n");
// #endif
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

				if ((will_write_if_dirty || will_evict) && (c->status & ERASER_CACHE_DIRTY)) {
// #ifdef HOLEPUNCH_DEBUG
// 					KWORKERMSG("Reaper persisting sector %u\n", c->sector);
// #endif
					holepunch_persist_unlink(rd, c, &rd->cache_lock[i]);
				}
				if (will_evict && (rd->map_cache_count > ERASER_CACHE_MEMORY_PRESSURE))
					eraser_drop_map_cache(rd, c);
			}
			up(&rd->cache_lock[i]);
		}

// #ifdef HOLEPUNCH_DEBUG
// 		down_read(&rd->map_cache_count_sem);
// 		KWORKERMSG("The reaper shall return for another bounty... (Cached: %llu)\n",
// 			rd->map_cache_count);
// 		up_read(&rd->map_cache_count_sem);
// #endif
		msleep_interruptible(ERASER_CACHE_EVICTION_PERIOD * 1000);

		/*
		 * We do simple & stupid sleep wait instead of signaling. Proper
		 * eviction strategies should be studied for optimal performance.
		 */
		if (kthread_should_stop()) {
// #ifdef HOLEPUNCH_DEBUG
// 			KWORKERMSG("The reaper bids farewell\n");
// #endif
			return 0;
		}

	}
	return 0; /* Never. */
}

/*
 * I/O mapping & encryption/decryption functions.
 */

/* Called when an encrypted clone bio is written to disk. */
static void eraser_encrypted_bio_end_io(struct bio *encrypted_bio)
{
	struct bio_vec vec;
	struct eraser_io_work *w = (struct eraser_io_work *)encrypted_bio->bi_private;

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

/* Bottom-half entry for write operations. */
static void eraser_do_write_bottomhalf(struct eraser_io_work *w)
{
	struct bio *clone, *encrypted_bio;
	struct bio_vec vec;
	struct page *p;
	u8 key[ERASER_KEY_LEN];

	if (w->is_file) {
		holepunch_get_inode_key(w->rd, key,
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino);
	} else {
		memcpy(key, w->rd->sec_key, ERASER_KEY_LEN);
	}

	/* Clone the original bio's pages, encrypt them, submit in a new bio. */
	encrypted_bio = eraser_allocate_bio_multi_vector(w->bio->bi_iter.bi_size / ERASER_SECTOR, w->rd);
	encrypted_bio->bi_bdev = w->bio->bi_bdev;
	encrypted_bio->bi_iter.bi_sector = w->bio->bi_iter.bi_sector;
	encrypted_bio->bi_rw = w->bio->bi_rw;
	encrypted_bio->bi_private = w;
	encrypted_bio->bi_end_io = &eraser_encrypted_bio_end_io;

	clone = bio_clone_fast(w->bio, GFP_NOIO, w->rd->bioset);
	while (clone->bi_iter.bi_size)
	{
		vec = bio_iter_iovec(clone, clone->bi_iter);
		bio_advance_iter(clone, &clone->bi_iter, vec.bv_len);

		p = eraser_allocate_page(w->rd);
		holepunch_cbc_sector(w->rd, kmap(p), kmap(vec.bv_page), ERASER_ENCRYPT,
			key, clone->bi_iter.bi_sector);
		kunmap(p);
		kunmap(vec.bv_page);
		bio_add_page(encrypted_bio, p, ERASER_SECTOR, 0);
	}

	submit_bio(0, encrypted_bio);
	bio_put(clone);
}

/* Bottom half entry for read operations. */
static void eraser_do_read_bottomhalf(struct eraser_io_work *w)
{
	struct bio *clone;
	struct bio_vec vec;
	u8 key[ERASER_KEY_LEN];

	if (w->is_file) {
		holepunch_get_inode_key(w->rd, key,
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino);
	} else {
		memcpy(key, w->rd->sec_key, ERASER_KEY_LEN);
	}

	/* Read is complete at this point. Simply iterate over pages and decrypt. */
	clone = bio_clone_fast(w->bio, GFP_NOIO, w->rd->bioset);
	while (clone->bi_iter.bi_size)
	{
		vec = bio_iter_iovec(clone, clone->bi_iter);
		bio_advance_iter(clone, &clone->bi_iter, vec.bv_len);

		holepunch_cbc_sector_inplace(w->rd, kmap(vec.bv_page), ERASER_DECRYPT,
			key, clone->bi_iter.bi_sector);
		kunmap(vec.bv_page);
	}

	bio_endio(w->bio);
	bio_put(w->bio);

	bio_put(clone);
	eraser_free_io_work(w);
}

/* I/O queues. */
static void eraser_do_io(struct work_struct *work)
{
	struct eraser_io_work *w = container_of(work, struct eraser_io_work, work);
	if (bio_data_dir(w->bio) == WRITE)
		eraser_do_write_bottomhalf(w);
	else
		eraser_do_read_bottomhalf(w);
}

static void eraser_queue_io(struct eraser_io_work *w)
{
	INIT_WORK(&w->work, eraser_do_io);
	queue_work(w->rd->io_queue, &w->work);
}

/* Called when the original bio's read is complete. Next we wil decrypt in the
 * bottom half. */
static void eraser_read_end_io(struct bio *clone)
{
	eraser_queue_io((struct eraser_io_work *)clone->bi_private);
	bio_put(clone);
}

/*
 * DM mapping function. This executes under make_generic_request(), and under
 * that function submit_bio() does not actually submit anything until we
 * return. This makes synchronous I/O impossible in this function, and we need
 * to do it for key retrieval. Therefore here we only set up a bottom half to do
 * the actual job later.
 */
static int eraser_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct bio *clone;
	struct eraser_io_work *w;
	struct eraser_dev *rd = (struct eraser_dev *)ti->private;

	if (unlikely(!rd->virt_dev))
		rd->virt_dev = bio->bi_bdev->bd_dev;

	bio->bi_bdev = rd->real_dev->bdev;
	// #ifdef HOLEPUNCH_DEBUG
	// 	DMINFO("request remapped from sector %u to sector %u\n", bio->bi_iter.bi_sector,
	// 							bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE));
	// #endif
	bio->bi_iter.bi_sector = bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE);

	if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
		return DM_MAPIO_REMAPPED;
	}

	if (bio_has_data(bio)) {
		/* if (unlikely(bio->bi_iter.bi_size % ERASER_SECTOR != 0)) { */
		/* 	DMCRIT("WARNING: Incorrect IO size! Something's terribly wrong!"); */
		/* 	DMCRIT("remapping... sector: %lu, size: %u", bio->bi_iter.bi_sector, bio->bi_iter.bi_size); */
		/* } */

		w = eraser_allocate_io_work(bio, rd);

		/* Perform a few NULL pointer checks, these things do happen
		 * when bio is not a read/write operation. */
		/* If this is file I/O... */
		if (bio_iter_iovec(bio, bio->bi_iter).bv_page &&
			bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping &&
			bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping->host &&
			S_ISREG(bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping->host->i_mode)) {
			w->is_file = 1; /* We will perform file encryption. */
		} else {
			w->is_file = 0; /* We will perform good old disk sector encryption. */
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
			clone = bio_clone_fast(bio, GFP_NOIO, rd->bioset);
			clone->bi_private = w;
			clone->bi_end_io = &eraser_read_end_io;
			submit_bio(0, clone);
			return DM_MAPIO_SUBMITTED;
		}
	}

	/* Remap everything else. */
	return DM_MAPIO_REMAPPED;
}

/*
 * Unlink functions.
 */

/* These first three actually journal rather than writing directly. */
/* Needs PPRF read lock held. */
static void holepunch_write_key_table_sector(struct eraser_dev *rd,
		struct holepunch_filekey_sector *sector, u64 index)
{
	struct page *p;
	struct holepunch_filekey_sector *data;
	u8 key[PRG_INPUT_LEN];
	u64 sectorno = rd->hp_h->key_table_start + index;

	p = eraser_allocate_page(rd);
	data = kmap(p);
	holepunch_evaluate_at_tag(rd, sector->tag, key, rd->pprf_key);
	holepunch_cbc_filekey_sector(rd, data, sector, ERASER_ENCRYPT, key, sectorno);
	holepunch_journal_write(rd, sectorno, data);
	kunmap(p);
	eraser_free_page(p, rd);
}

static void holepunch_write_fkt_bottom_sector(struct eraser_dev *rd,
		u64 index, char *map)
{
	u64 sectorno;
	u8 *key = holepunch_fkt_bottom_key(rd, index);
	kernel_random(key, ERASER_KEY_LEN);

	sectorno = rd->hp_h->fkt_start + index / HP_FKT_PER_SECTOR;
	holepunch_cbc_sector(rd, map, rd->pprf_fkt + index / HP_FKT_PER_SECTOR,
		ERASER_ENCRYPT, rd->master_key, sectorno);
	holepunch_journal_write(rd, sectorno, map);

	sectorno = rd->hp_h->fkt_start + rd->hp_h->fkt_top_width + index;
	holepunch_cbc_sector(rd, map, rd->pprf_fkt + rd->hp_h->fkt_top_width + index,
		ERASER_ENCRYPT, key, sectorno);
	holepunch_journal_write(rd, sectorno, map);
}

static void holepunch_write_pprf_key_sector(struct eraser_dev *rd, u64 index,
	char *map, bool fkt_refresh)
{
	u8 *key = holepunch_pprf_key(rd, index);
	if (fkt_refresh) {
		kernel_random(key, ERASER_KEY_LEN);
		holepunch_write_fkt_bottom_sector(rd, index / HP_FKT_PER_SECTOR, map);
	}
	holepunch_cbc_sector(rd, map, rd->pprf_key + index * HP_PPRF_PER_SECTOR,
		ERASER_ENCRYPT, key, rd->hp_h->pprf_start + index);
	holepunch_journal_write(rd, rd->hp_h->pprf_start + index, map);
}

/*
 * Lock cache bucket from outside, but also pass it in, in case refresh needed.
 * Takes the PPRF write lock.
 */
static void holepunch_persist_unlink(struct eraser_dev *rd,
		struct eraser_map_cache *c, struct semaphore *cache_lock)
{
	u32 punctured_index, start_index, end_index;
	u32 punctured_sector, start_sector, end_sector;
	u64 old_tag, s;
	struct page *p;
	void *map;
	struct pprf_keynode *new_key; /* Only used if expansion needed. */

	/* If we refresh the PPRF, then we don't need to puncture again afterwards */
	if (rd->hp_h->pprf_size + 2*rd->hp_h->pprf_depth > rd->hp_h->pprf_capacity) {
		HP_UP(cache_lock, "PPRF: persist -> refresh");
		eraser_force_evict_map_cache(rd, 0);
		HP_DOWN_WRITE(&rd->pprf_sem, "PPRF: persist -> refresh");
		++rd->stats_refresh;
		holepunch_rotate_pprf(rd);
		HP_UP_WRITE(&rd->pprf_sem, "PPRF: persist -> refresh");
		HP_DOWN(cache_lock, "PPRF: reacquire");
		return;
	}

	HP_DOWN_WRITE(&rd->pprf_sem, "PPRF: persist unlink");
	/* proceed with puncturing */
	old_tag = c->map->tag;
	c->map->tag = rd->hp_h->tag_counter++;
#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Tag: %llu -> %llu\n", old_tag, c->map->tag);
	KWORKERMSG("Keylength before: %u/%u, limit: %u\n", rd->hp_h->pprf_size,
		rd->pprf_key_capacity, rd->hp_h->pprf_capacity);
#endif

	start_index = rd->hp_h->pprf_size;
	punctured_index = puncture_at_tag(rd->pprf_key, rd->hp_h->pprf_depth,
		holepunch_prg_generic, rd, &rd->hp_h->pprf_size, old_tag);
	end_index = rd->hp_h->pprf_size;

	/* Expand the in-memory pprf key if needed. */
	if (rd->hp_h->pprf_size + 2 * rd->hp_h->pprf_depth > rd->pprf_key_capacity) {
		new_key = vmalloc(rd->pprf_key_capacity * HP_PPRF_EXPANSION_FACTOR
			* sizeof(struct pprf_keynode));
		/*
		 * TODO for now we just ignore errors, but we should probably do
		 * something about them
		 */
		if (!new_key)
			DMERR("Insufficient memory!");
		rd->pprf_key_capacity *= HP_PPRF_EXPANSION_FACTOR;
		vfree(rd->pprf_key);
		rd->pprf_key = new_key;
	}
	++rd->stats_puncture;

	punctured_sector = punctured_index / HP_PPRF_PER_SECTOR;
	start_sector = start_index / HP_PPRF_PER_SECTOR;
	end_sector = (end_index - 1) / HP_PPRF_PER_SECTOR;

#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Keylength after: %u/%u, limit: %u\n", rd->hp_h->pprf_size,
		rd->pprf_key_capacity, rd->hp_h->pprf_capacity);
	KWORKERMSG("PPRF keynode indices touched: %u %u %u\n",
		punctured_index, start_index, end_index - 1);
	KWORKERMSG("PPRF keynode sectors touched: %u %u %u\n",
		punctured_sector, start_sector, end_sector);
#endif
	/* Persists new crypto information to disk */
	p = eraser_allocate_page(rd);
	map = kmap(p);

	holepunch_write_pprf_key_sector(rd, punctured_sector, map, true);
	if (start_sector > punctured_sector) {
		for (s = start_sector; s <= end_sector; ++s) {
			holepunch_write_pprf_key_sector(rd, s, map, false);
		}
	}
	kunmap(p);
	eraser_free_page(p, rd);
	holepunch_write_key_table_sector(rd, c->map, c->sector);
	c->status = 0;
	holepunch_journal_write(rd, 0, rd->hp_h);
	holepunch_journal_commit(rd);
	HP_UP_WRITE(&rd->pprf_sem, "PPRF: persist unlink");
	holepunch_rotate_master(rd);
#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Persist successful\n");
#endif
}

/* Bottom half for unlink operations. */
static void holepunch_do_unlink(struct work_struct *work)
{
	struct eraser_map_cache *c;
	struct semaphore *cache_lock;
	struct eraser_unlink_work *w = container_of(work, struct eraser_unlink_work, work);
	c = holepunch_get_cache_entry(w->rd, w->ino, &cache_lock);
	kernel_random(c->map->entries[w->ino % HP_KEY_PER_SECTOR].key, ERASER_KEY_LEN);
	c->status = ERASER_CACHE_DIRTY;
	c->last_dirty = jiffies;
#ifndef HOLEPUNCH_BATCHING
	holepunch_persist_unlink(w->rd, c, cache_lock);
#endif
	HP_UP(cache_lock, "Cache: unlink");
	eraser_free_unlink_work(w);
}

static void eraser_queue_unlink(struct eraser_unlink_work *w)
{
	INIT_WORK(&w->work, holepunch_do_unlink);
	queue_work(w->rd->unlink_queue, &w->work);
}

/* kprobe for vfs_unlink. */
static int eraser_unlink_kprobe_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct eraser_dev *rd;
	struct eraser_unlink_work *w;
	struct inode *dir = (struct inode *)regs->di;
	struct dentry *victim = (struct dentry *)regs->si;

	struct inode *inode = d_backing_inode(victim);

	/* Perform all permission checks first, maybe we cannot delete. */
	if (d_is_negative(victim) || !inode || !inode->i_sb || !inode->i_sb->s_bdev
		|| victim->d_parent->d_inode != dir
		|| inode_permission(dir, MAY_WRITE | MAY_EXEC) || IS_APPEND(dir)
		|| (check_sticky(dir, inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode)
		|| IS_SWAPFILE(inode)) || d_is_dir(victim) || IS_DEADDIR(dir))
		return 0;

	/* Queue an unlink work for the proper ERASER instance. */
	list_for_each_entry(rd, &eraser_dev_list, list) {
		if (rd->virt_dev == inode->i_sb->s_bdev->bd_dev) {
			w = eraser_allocate_unlink_work(inode->i_ino, rd);
			eraser_queue_unlink(w);
			break;
		}
	}

	return 0;
}

static struct kprobe eraser_unlink_kprobe = {
	.symbol_name = "vfs_unlink",
	.pre_handler = eraser_unlink_kprobe_entry,
};

/*
 * Netlink.
 */

#define ERASER_NETLINK 31
#define ERASER_MSG_PAYLOAD (ERASER_NAME_LEN + ERASER_KEY_LEN)

enum
{
	ERASER_MSG_GET_KEY,
	ERASER_MSG_SET_KEY,
	ERASER_MSG_DIE,
};

static struct sock *eraser_sock;

/* Rather, we ask it to die nicely. */
static int eraser_kill_helper(struct eraser_dev *rd)
{
	struct nlmsghdr *h;
	struct sk_buff *skb_out;

	skb_out = nlmsg_new(0, GFP_KERNEL);
	if (!skb_out)
		DMWARN("Cannot allocate sk_buff.");

	h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_DIE, 0, GFP_KERNEL);
	if (!h)
		DMWARN("Cannot put msg.");

	NETLINK_CB(skb_out).dst_group = 0;

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
		DMWARN("Cannot send DIE.");
		return ERASER_ERROR;
	}

	return ERASER_SUCCESS;
}

/* Request the master key. */
static int eraser_get_master_key(struct eraser_dev *rd)
{
	struct nlmsghdr *h;
	struct sk_buff *skb_out;
	unsigned char *payload;

	skb_out = nlmsg_new(ERASER_MSG_PAYLOAD, GFP_KERNEL);
	if (!skb_out)
		DMWARN("Cannot allocate sk_buff.");

	h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_GET_KEY, ERASER_MSG_PAYLOAD, GFP_KERNEL);
	if (!h)
		DMWARN("Cannot put msg.");

	NETLINK_CB(skb_out).dst_group = 0;

	payload = nlmsg_data(h);
	memset(payload, 0, ERASER_MSG_PAYLOAD);
	memcpy(payload, rd->eraser_name, ERASER_NAME_LEN);

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
		DMWARN("Cannot send GET KEY.");
		return ERASER_ERROR;
	}

	return ERASER_SUCCESS;
}

/* Sync a new master key. */
static int eraser_set_master_key(struct eraser_dev *rd)
{
	struct nlmsghdr *h;
	struct sk_buff *skb_out;
	unsigned char *payload;

	skb_out = nlmsg_new(ERASER_MSG_PAYLOAD, GFP_KERNEL);
	if (!skb_out)
		DMWARN("Cannot allocate sk_buff.");

	h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_SET_KEY, ERASER_MSG_PAYLOAD, 0);
	if (!h)
		DMWARN("Cannot put msg.");

	NETLINK_CB(skb_out).dst_group = 0;

	payload = nlmsg_data(h);
	memset(payload, 0, ERASER_MSG_PAYLOAD);
	memcpy(payload, rd->eraser_name, ERASER_NAME_LEN);
	holepunch_ecb(rd, payload + ERASER_NAME_LEN, rd->new_master_key,
		ERASER_KEY_LEN, ERASER_ENCRYPT, rd->sec_key);

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0) {
		DMWARN("Cannot send SET KEY.");
		return ERASER_ERROR;
	}

	return ERASER_SUCCESS;
}

/* Netlink message receive callback. */
static void eraser_netlink_recv(struct sk_buff *skb_in)
{
	struct eraser_dev *rd;
	struct nlmsghdr *h;
	unsigned char *payload;
	int len;
	u8 name[ERASER_NAME_LEN + 1];
	int found;

	h = (struct nlmsghdr *)skb_in->data;
	payload = nlmsg_data(h);
	len = nlmsg_len(h);

	if (len != ERASER_MSG_PAYLOAD) {
		DMERR("Unknown message format.");
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

	if (!found)	{
		DMERR("Message to unknown device.");
		return;
	}

	/* Now rd holds our device. */
	if (h->nlmsg_type == ERASER_MSG_GET_KEY) {
		/* We got the master key. */
		DMINFO("Received master key.");
		if (test_and_clear_bit(ERASER_KEY_GET_REQUESTED, &rd->master_key_status)) {
			holepunch_ecb(rd, rd->master_key, payload + ERASER_NAME_LEN,
				ERASER_KEY_LEN, ERASER_DECRYPT, rd->sec_key);

			set_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status);
			complete(&rd->master_key_wait);
		} else {
			DMWARN("Received unsolicited key. Dropping.");
		}
	}
	else if (h->nlmsg_type == ERASER_MSG_SET_KEY) {
		/* We got confirmation that master key is synched to the vault. */
#ifdef HOLEPUNCH_DEBUG
		DMINFO("Received key sync ACK.");
#endif
		if (test_and_clear_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status)) {
			set_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status);
			complete(&rd->master_key_wait);
		} else {
			DMWARN("Received unsolicited ACK. Dropping.");
		}
	} else {
		DMERR("Unknown message type.");
	}

	/* TODO: Do *we* free the sk_buff here? Somebody please document netlink
	 * properly! */
}

// TODO this could be simpler (one netlink send function too)
static void holepunch_tpm_set_master(struct eraser_dev *rd, u8 *new_key)
{
	memcpy(rd->new_master_key, new_key, ERASER_KEY_LEN);
	__set_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status);
	while (eraser_set_master_key(rd)) {
		msleep(100);
	}
	msleep(10);
	while (!test_and_clear_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status)) {
		wait_for_completion_timeout(&rd->master_key_wait, 1 * HZ);
	}
	memcpy(rd->master_key, rd->new_master_key, ERASER_KEY_LEN);
}


static struct netlink_kernel_cfg eraser_netlink_cfg =
{
	.input = eraser_netlink_recv,
	.groups = 0,
	.flags = 0,
	.cb_mutex = NULL,
	.bind = NULL,
};

#ifdef HOLEPUNCH_DEBUG
static void dump_key(u8 *key, const char *name)
{
	char *buf;
	int i;
	buf = kmalloc(ERASER_KEY_LEN * 3 + 1, GFP_KERNEL);
	for (i = 0; i < ERASER_KEY_LEN; ++i) {
		sprintf(buf + i * 3, "%02hhx ", key[i]);
	}
	buf[ERASER_KEY_LEN * 3] = '\0';
	DMINFO("%s: %s", name, buf);
	kfree(buf);
}
#endif

/*
 * Constructor.
 */
static int eraser_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct eraser_dev *rd;
	char dummy;
	int helper_pid, i;
	u8 hash[HP_HASH_LEN];
	u8 new_key[ERASER_KEY_LEN];
	int need_master_rot = 0;

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

	DMINFO("Creating ERASER on %s", argv[0]);

	if (sscanf(argv[4], "%d%c", &helper_pid, &dummy) != 1)
	{
		ti->error = "Invalid arguments.";
		return -EINVAL;
	}
	DMINFO("Helper PID: %d", helper_pid);

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

	/* Decode disk encryption key. */
	// TODO add error checking for kalloc failing or invalid hex (could probably
	// also make key fixed-length instead of kallocing)
	rd->sec_key = eraser_hex_decode(argv[2]);
	/* We don't need the key argument anymore, wipe it clean. */
	memset(argv[2], 0, strlen(argv[2]));

	/* Initialize crypto. */
	rd->cpus = num_online_cpus();
	rd->ecb_tfm = kmalloc(rd->cpus * sizeof *rd->ecb_tfm, GFP_KERNEL);
	for (i = 0; i < rd->cpus; ++i) {
		rd->ecb_tfm[i] = crypto_alloc_blkcipher("ecb(aes)", 0, 0);
		if (IS_ERR(rd->ecb_tfm[i])) {
			ti->error = "Could not create ecb crypto transform.";
			goto init_ecb_tfm_fail;
		}
	}
	rd->cbc_tfm = kmalloc(rd->cpus * sizeof *rd->cbc_tfm, GFP_KERNEL);
	for (i = 0; i < rd->cpus; ++i) {
		rd->cbc_tfm[i] = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
		if (IS_ERR(rd->cbc_tfm[i])) {
			ti->error = "Could not create cbc crypto transform.";
			goto init_cbc_tfm_fail;
		}
	}
	rd->ctr_tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(rd->ctr_tfm)) {
		ti->error = "Could not create ctr crypto transform.";
		goto init_ctr_tfm_fail;
	}
	rd->sha_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(rd->sha_tfm)) {
		ti->error = "Could not create sha256 hash transform.";
		goto init_sha_tfm_fail;
	}
	rd->prg_input = kzalloc(ERASER_KEY_LEN * 2, GFP_KERNEL);
	if (!rd->prg_input) {
		goto init_prg_input_fail;
	}
	for (i = 0; i < ERASER_KEY_LEN * 2; i += ERASER_KEY_LEN / 2) {
		rd->prg_input[i] = i;
	}

	/* Get the master key. */
	init_completion(&rd->master_key_wait);
	rd->master_key_status = 0;
	__set_bit(ERASER_KEY_GET_REQUESTED, &rd->master_key_status);
	while (eraser_get_master_key(rd) != ERASER_SUCCESS) {
		DMWARN("Cannot send GET master key. Will retry.");
		msleep(3000);
	}
	while (!test_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status)) {
		DMINFO("Waiting for master key.");
		wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
	}

	/* Create bioset and page pool. */
	rd->bioset = bioset_create(ERASER_BIOSET_SIZE, 0);
	if (!rd->bioset)
	{
		ti->error = "Could not create bioset.";
		goto create_bioset_fail;
	}

	rd->page_pool = mempool_create_page_pool(ERASER_PAGE_POOL_SIZE, 0);
	if (!rd->page_pool)
	{
		ti->error = "Could not create page pool.";
		goto create_page_pool_fail;
	}

	/* Read header from disk. */
	// TODO allocate this (for multiple lengths, too) and handle failure
	holepunch_read_header(rd);
	if (rd->hp_h->journal_start != ERASER_HEADER_LEN) {
		ti->error = "Bad header length.";
		goto read_header_fail;
	}
	if (rd->hp_h->key_table_start - rd->hp_h->journal_start != HP_JOURNAL_LEN) {
		ti->error = "Bad journal length.";
		goto read_header_fail;
	}
	rd->key_table_len = rd->hp_h->fkt_start - rd->hp_h->key_table_start;
	rd->fkt_len = rd->hp_h->pprf_start - rd->hp_h->fkt_start;
	if (rd->hp_h->fkt_top_width + rd->hp_h->fkt_bottom_width != rd->fkt_len) {
		ti->error = "Bad PPRF FKT length.";
		goto read_header_fail;
	}
	rd->pprf_len = rd->hp_h->data_start - rd->hp_h->pprf_start;
	if (rd->hp_h->pprf_capacity * sizeof(struct pprf_keynode) / ERASER_SECTOR > rd->pprf_len) {
		DMINFO("Cap: %u", rd->hp_h->pprf_capacity);
		DMINFO("Size: %lu", sizeof(struct pprf_keynode));
		DMINFO("Len: %llu", rd->pprf_len);
		ti->error = "Bad PPRF key length.";
		goto read_header_fail;
	}
	rd->data_len = rd->hp_h->data_end - rd->hp_h->data_start;
#ifdef HOLEPUNCH_DEBUG
	DMINFO("Header start: %d", 0);
	DMINFO("Header sectors: %d", ERASER_HEADER_LEN);

	DMINFO("Journal start: %llu", rd->hp_h->journal_start);
	DMINFO("Journal sectors: %d", HP_JOURNAL_LEN);

	DMINFO("Key table start: %llu", rd->hp_h->key_table_start);
	DMINFO("Key table sectors: %llu", rd->key_table_len);

	DMINFO("PPRF fkt start: %llu", rd->hp_h->fkt_start);
	DMINFO("PPRF fkt sectors: %llu", rd->fkt_len);

	DMINFO("PPRF key start: %llu", rd->hp_h->pprf_start);
	DMINFO("PPRF key sectors: %llu", rd->pprf_len);

	DMINFO("Data start: %llu", rd->hp_h->data_start);
	DMINFO("Data sectors: %llu", rd->data_len);
#endif

	/* Work caches and queues. */
	rd->_io_work_pool = KMEM_CACHE(eraser_io_work, 0);
	if (!rd->_io_work_pool) {
		ti->error = "Could not create io cache.";
		goto create_io_cache_fail;
	}

	rd->io_work_pool = mempool_create_slab_pool(ERASER_IO_WORK_POOL_SIZE, rd->_io_work_pool);
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

	rd->unlink_work_pool = mempool_create_slab_pool(ERASER_UNLINK_WORK_POOL_SIZE, rd->_unlink_work_pool);
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

	rd->map_cache_pool = mempool_create_slab_pool(ERASER_MAP_CACHE_POOL_SIZE, rd->_map_cache_pool);
	if (!rd->map_cache_pool) {
		ti->error = "Could not create map cache pool.";
		goto create_map_cache_pool_fail;
	}

	for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
		INIT_LIST_HEAD(&rd->map_cache_list[i]);
		sema_init(&rd->cache_lock[i], 1);
	}

	rd->map_cache_count = 0;

	/* PPRF key and FKT. */
	rd->pprf_fkt = vmalloc(rd->fkt_len * ERASER_SECTOR);
	if (!rd->pprf_fkt) {
		ti->error = "Could not allocate pprf fkt.";
		goto alloc_pprf_fkt_fail;
	}
	rd->pprf_key_capacity = round_up(2*rd->hp_h->pprf_size, HP_PPRF_PER_SECTOR);
	rd->pprf_key = vmalloc(rd->pprf_key_capacity * sizeof(struct pprf_keynode));
	if (!rd->pprf_key) {
		ti->error = "Could not allocate pprf key.";
		goto alloc_pprf_key_fail;
	}
	holepunch_read_fkt(rd);
	holepunch_read_pprf(rd);

	/* Journal recovery, if necessary. */
	rd->journal_entry = 0;
	rd->journal = eraser_rw_sector(rd->hp_h->journal_start, READ, NULL, rd);
	switch (rd->journal[0]) {
		case HPJ_NONE:
			break;
		case HPJ_MASTER_ROT:
			DMINFO("Recovering master key rotation");
			holepunch_hash(rd, rd->master_key, ERASER_KEY_LEN, hash);
			if (!memcmp(hash, (void *) rd->journal + 8 + ERASER_KEY_LEN, HP_HASH_LEN)) {
				/* TPM still contains old key. */
				holepunch_ecb(rd, new_key, rd->journal + 1, ERASER_KEY_LEN,
					ERASER_DECRYPT, rd->master_key);
				holepunch_do_master_rotation(rd, new_key);
			}
			goto journal_clear;
		case HPJ_PPRF_ROT:
			DMINFO("Recovering PPRF key rotation");
			holepunch_do_pprf_rotation(rd, new_key, 0);
			need_master_rot = 1;
			goto journal_clear;
		case HPJ_PPRF_INIT:
			DMINFO("Recovering PPRF key initialization");
			holepunch_do_pprf_rotation(rd, new_key, 1);
			goto journal_clear;
		case HPJ_GENERIC:
			DMINFO("Recovering journalled write");
			holepunch_journal_replay(rd);
			goto journal_clear;
		default:
			DMWARN("Invalid journal control type; ignoring");
		journal_clear:
			rd->journal[0] = HPJ_NONE;
			eraser_rw_sector(rd->hp_h->journal_start, WRITE, rd->journal, rd);
			break;
	}
	eraser_free_sector(rd->journal, rd);
	rd->journal = NULL;

	/* Rotate master key if there was a non-journalled crash. */
	if (unlikely(rd->hp_h->in_use)) {
		need_master_rot = 1;
	} else {
		rd->hp_h->in_use = 1;
		holepunch_write_header(rd);
	}
	if (need_master_rot) {
		holepunch_rotate_master(rd);
	}

	rd->evict_map_cache_thread = kthread_run(&holepunch_evict_map_cache, rd, "holepunch_evict");
	if (IS_ERR(rd->evict_map_cache_thread)) {
		ti->error = "Could not create cache evict thread.";
		goto create_evict_thread_fail;
	}

	init_rwsem(&rd->pprf_sem);

	// TODO catch errors here
	rd->real_dev_path = kmalloc(strlen(argv[0]) + 1, GFP_KERNEL);
	strcpy(rd->real_dev_path, argv[0]);
	rd->virt_dev_path = kmalloc(strlen(argv[3]) + 1, GFP_KERNEL);
	strcpy(rd->virt_dev_path, argv[3]);

	ti->num_discard_bios = 1;
	ti->private = rd;

	rd->stats_evaluate = 0;
	rd->stats_puncture = 0;
	rd->stats_refresh = 0;
#ifdef HOLEPUNCH_DEBUG
	dump_key(rd->master_key, "Master key");
	dump_key(rd->sec_key, "Sector key");
	dump_key(rd->hp_h->iv_key, "IV key");
#endif
	return 0;

	/* Lots to clean up after an error. */
create_evict_thread_fail:
	vfree(rd->pprf_key);
alloc_pprf_key_fail:
	vfree(rd->pprf_fkt);
alloc_pprf_fkt_fail:
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
	eraser_free_sector(rd->hp_h, rd);
read_header_fail:
	mempool_destroy(rd->page_pool);
create_page_pool_fail:
	bioset_free(rd->bioset);
create_bioset_fail:
	kfree(rd->prg_input);
init_prg_input_fail:
	crypto_free_shash(rd->sha_tfm);
init_sha_tfm_fail:
	crypto_free_blkcipher(rd->ctr_tfm);
init_ctr_tfm_fail:
	i = rd->cpus;
init_cbc_tfm_fail:
	/* We may have created some of the transforms. */
	for (i = i - 1; i >= 0; --i)
		crypto_free_blkcipher(rd->cbc_tfm[i]);
	kfree(rd->cbc_tfm);
	i = rd->cpus;
init_ecb_tfm_fail:
	/* We may have created some of the transforms. */
	for (i = i - 1; i >= 0; --i)
		crypto_free_blkcipher(rd->ecb_tfm[i]);
	kfree(rd->ecb_tfm);
	kfree(rd->sec_key);
	down(&eraser_dev_lock);
	eraser_destroy_dev(ti, rd);
create_dev_fail:
lookup_dev_fail:
	up(&eraser_dev_lock);
	/* Wipe key argument. */
	memset(argv[2], 0, strlen(argv[2]));

	return -EINVAL;
}

/*
 * Destructor.
 */
static void eraser_dtr(struct dm_target *ti)
{
	struct eraser_dev *rd = (struct eraser_dev *)ti->private;
	unsigned i;

	// TODO is this lock necessary (even if it is, is it needed for the whole
	// thing)?
	HP_DOWN_WRITE(&rd->pprf_sem, "PPRF on DTR");
	DMINFO("Destroying.");

	kfree(rd->real_dev_path);
	kfree(rd->virt_dev_path);

	/* Stop auto eviction and write back cached maps. */
	kthread_stop(rd->evict_map_cache_thread);

	DMINFO("evict cache");
	eraser_force_evict_map_cache(rd, 1);

	/* Keys no longer needed, wipe them. */
	eraser_kill_helper(rd);
	memset(rd->new_master_key, 0, ERASER_KEY_LEN);
	memset(rd->master_key, 0, ERASER_KEY_LEN);
	memset(rd->sec_key, 0, ERASER_KEY_LEN);

	DMINFO("write header");
	/* Write header. */
	holepunch_write_header(rd);
	eraser_free_sector(rd->hp_h, rd);

	vfree(rd->pprf_key);
	vfree(rd->pprf_fkt);

	/* Clean up. */
	mempool_destroy(rd->map_cache_pool);
	kmem_cache_destroy(rd->_map_cache_pool);

	destroy_workqueue(rd->unlink_queue);
	mempool_destroy(rd->unlink_work_pool);
	kmem_cache_destroy(rd->_unlink_work_pool);

	destroy_workqueue(rd->io_queue);
	mempool_destroy(rd->io_work_pool);
	kmem_cache_destroy(rd->_io_work_pool);

	mempool_destroy(rd->page_pool);
	bioset_free(rd->bioset);

	kfree(rd->prg_input);
	crypto_free_shash(rd->sha_tfm);
	crypto_free_blkcipher(rd->ctr_tfm);
	for (i = 0; i < rd->cpus; ++i)
		crypto_free_blkcipher(rd->cbc_tfm[i]);
	kfree(rd->cbc_tfm);

	for (i = 0; i < rd->cpus; ++i)
		crypto_free_blkcipher(rd->ecb_tfm[i]);
	kfree(rd->ecb_tfm);

	kfree(rd->sec_key);

	down(&eraser_dev_lock);
	eraser_destroy_dev(ti, rd);
	up(&eraser_dev_lock);
	HP_UP_WRITE(&rd->pprf_sem, "PPRF on DTR");

	KWORKERMSG("== Usage stats ==\nEvals: %llu\nPunctures: %llu\nRefreshes: %llu\n",
		rd->stats_evaluate, rd->stats_puncture, rd->stats_refresh);

	DMINFO("Success.");
}

static void eraser_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
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
	.io_hints = eraser_io_hints,
};

static void config_messages(void)
{
#ifdef HOLEPUNCH_BATCHING
	DMINFO("Batching enabled");
#else
	DMINFO("Batching disabled");
#endif
#ifdef HOLEPUNCH_DEBUG
	DMINFO("HOLEPUNCH compiled in debug mode");
#endif
	DMINFO("HP_PPRF_PER_SECTOR: %lu", HP_PPRF_PER_SECTOR);
	DMINFO("HP_FKT_PER_SECTOR: %d", HP_FKT_PER_SECTOR);
	DMINFO("HP_KEY_PER_SECTOR: %d", HP_KEY_PER_SECTOR);
}


/* Module entry. */
static int __init dm_eraser_init(void)
{
	int r;

#ifdef HOLEPUNCH_PPRF_TEST
	run_tests();
#endif
#ifdef HOLEPUNCH_PPRF_TIME
	preliminary_benchmark();
#endif
	eraser_sock = netlink_kernel_create(&init_net, ERASER_NETLINK, &eraser_netlink_cfg);
	if (!eraser_sock) {
		DMERR("Netlink setup failed.");
		return -1;
	}

	r = register_kprobe(&eraser_unlink_kprobe);
	if (r < 0) {
		DMERR("Register kprobe failed %d", r);
		return r;
	}

	r = dm_register_target(&eraser_target);
	if (r < 0) {
		DMERR("dm_register failed %d", r);
		return r;
	}

	if (!proc_create(HOLEPUNCH_PROC_FILE, 0, NULL, &eraser_fops)) {
		DMERR("Cannot create proc file.");
		return -ENOMEM;
	}

	config_messages();

	return r;
}

/* Module exit. */
static void __exit dm_eraser_exit(void)
{
	remove_proc_entry(HOLEPUNCH_PROC_FILE, NULL);
	dm_unregister_target(&eraser_target);
	unregister_kprobe(&eraser_unlink_kprobe);
	netlink_kernel_release(eraser_sock);
	DMINFO("HOLEPUNCH unloaded.");
}

module_init(dm_eraser_init);
module_exit(dm_eraser_exit);

MODULE_DESCRIPTION(DM_NAME " HOLEPUNCH target, based on ERASER");
MODULE_AUTHOR("Wittmann Goh");
MODULE_LICENSE("GPL");
