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
 * Memory pool management functions. Nothing to see here.
 */

static struct page *eraser_allocate_page(struct eraser_dev *rd)
{
	struct page *p;

	p = mempool_alloc(rd->page_pool, GFP_KERNEL);
	if (!p)
		DMCRIT("Cannot allocate new page!");

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
		DMCRIT("Cannot allocate new bio!");

	return b;
}

static struct bio *eraser_allocate_bio(struct eraser_dev *rd)
{
	struct bio *b;

	b = eraser_allocate_bio_multi_vector(1, rd);
	if (!b)
		DMCRIT("Cannot allocate new bio!");

	return b;
}

static struct eraser_io_work *eraser_allocate_io_work(struct bio *bio, struct eraser_dev *rd)
{
	struct eraser_io_work *w;

	w = mempool_alloc(rd->io_work_pool, GFP_NOIO);
	if (!w)
	{
		DMCRIT("Cannot allocate new io work!");
	}
	else
	{
		w->bio = bio;
		w->rd = rd;
	}
	return w;
}

static inline void eraser_free_io_work(struct eraser_io_work *w)
{
	mempool_free(w, w->rd->io_work_pool);
}

static struct eraser_unlink_work *eraser_allocate_unlink_work(unsigned long inode_no, struct eraser_dev *rd)
{
	struct eraser_unlink_work *w;

	w = mempool_alloc(rd->unlink_work_pool, GFP_ATOMIC);
	if (!w)
	{
		DMCRIT("Cannot allocate new unlink work!");
	}
	else
	{
		w->inode_no = inode_no;
		w->rd = rd;
	}
	return w;
}

static inline void eraser_free_unlink_work(struct eraser_unlink_work *w)
{
	mempool_free(w, w->rd->unlink_work_pool);
}

// static struct eraser_map_cache *eraser_allocate_map_cache(struct eraser_dev *rd)
// {
// 	struct eraser_map_cache *c;

// 	c = mempool_alloc(rd->map_cache_pool, GFP_NOIO);
// 	if (!c)
// 		DMCRIT("Cannot allocate new map cache!");

// 	memset(c, 0, sizeof(*c));
// 	return c;
// }

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

	if (__eraser_lookup_dev(dev_path, &dev) == ERASER_ERROR)
	{
		DMCRIT("Device lookup failed!");
		return NULL;
	}

	list_for_each_entry(cur, &eraser_dev_list, list)
	{
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

	if (rw == WRITE && !write_buf)
	{
		DMCRIT("Write buffer is NULL, aborting");
		return NULL;
	}

	bio = eraser_allocate_bio(rd);
	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = sector * ERASER_SECTOR_SCALE;

	if (rw == READ)
	{
		p = eraser_allocate_page(rd);
		bio->bi_rw &= ~REQ_WRITE;
	}
	else
	{
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

/* Reads and returns the ERASER header from disk. */
static inline struct eraser_header *eraser_read_header(struct eraser_dev *rd)
{
	return (struct eraser_header *)eraser_rw_sector(0, READ, NULL, rd);
}

/* Writes the ERASER header back to disk. */
static inline void eraser_write_header(struct eraser_header *rh, struct eraser_dev *rd)
{
	eraser_rw_sector(0, WRITE, (char *)rh, rd);
}

/*
 * Random data helpers.
 */

/* Returns crypto-safe random bytes from kernel pool. */
static inline void eraser_get_random_bytes_kernel(u8 *data, u64 len)
{
	crypto_get_default_rng();
	crypto_rng_get_bytes(crypto_default_rng, data, len);
	crypto_put_default_rng();
}

/* Sets a new random AES-CTR key if necessary and refreshes the random data
 * buffer. */
static void eraser_fill_rand_buf(struct eraser_rand_context *rand)
{
	u8 key[32];
	struct scatterlist src;
	struct scatterlist dst;
	struct blkcipher_desc desc;

	/* Refresh the key. */
	if (rand->cur_chunk == rand->max_chunk)
	{
		eraser_get_random_bytes_kernel(key, 32);
		crypto_blkcipher_setkey(rand->tfm, key, 32);
		memset(key, 0, 32);

		rand->cur_chunk = 0;
	}

	sg_init_table(&src, 1);
	sg_init_table(&dst, 1);

	sg_set_buf(&src, rand->buf, rand->max_byte);
	sg_set_buf(&dst, rand->buf, rand->max_byte);

	desc.tfm = rand->tfm;
	desc.flags = 0;

	if (crypto_blkcipher_encrypt(&desc, &dst, &src, rand->max_byte))
		DMCRIT("Error generating random stream");

	++(rand->cur_chunk);
	rand->cur_byte = 0;
}

/* Generates random bytes using the passed AES-CTR context. */
static void eraser_get_random_bytes(u8 *data, u64 len, struct eraser_dev *rd)
{
	u64 left;
	u64 read;
	struct eraser_rand_context *rand = &rd->rand[get_cpu()];

	while (len)
	{
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
static inline void eraser_get_random_iv(u8 *iv, struct eraser_dev *rd)
{
	eraser_get_random_bytes(iv, ERASER_IV_LEN, rd);
}

/* Fills a buffer with a random key. */
static inline void eraser_get_random_key(u8 *key, struct eraser_dev *rd)
{
	eraser_get_random_bytes(key, ERASER_KEY_LEN, rd);
}

static int holepunch_alloc_master_key(struct eraser_dev *rd, unsigned sectors)
{
	vfree(rd->pprf_master_key);
	rd->pprf_master_key = vmalloc(ERASER_SECTOR * sectors);
	if (!rd->pprf_master_key)
	{
		return -ENOMEM;
	}
	rd->pprf_master_key_capacity = sectors * HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR;
	return 0;
}

static int holepunch_expand_master_key(struct eraser_dev *rd, unsigned factor)
{
	void *tmp;
	unsigned old_size;

#ifdef DEBUG
	printk("RESIZING: current capacity = %u\n", rd->pprf_master_key_capacity);
#endif

	old_size = ERASER_SECTOR * (rd->pprf_master_key_capacity / HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR);
	tmp = vmalloc(factor * old_size);
	if (!tmp)
	{
		return -ENOMEM;
	}
	memcpy(tmp, rd->pprf_master_key, old_size);
	vfree(rd->pprf_master_key);
	rd->pprf_master_key = tmp;
	rd->pprf_master_key_capacity *= factor;

#ifdef DEBUG
	printk("RESIZING DONE: final capacity = %u\n", rd->pprf_master_key_capacity);
#endif
	return 0;
}

static void holepunch_init_master_key(struct eraser_dev *rd)
{
	memset(rd->pprf_master_key, 0, ERASER_SECTOR);
#ifndef DEBUG
	eraser_get_random_bytes_kernel(rd->pprf_master_key->entries[0].key, PRG_INPUT_LEN);
#endif
	rd->hp_h->master_key_count = 1;
}

// for sanity's sake we assume that the first node is the first array entry
struct pprf_keynode *holepunch_get_keynode_by_index(void *ptr, unsigned index)
{
	struct holepunch_pprf_keynode_sector *first_sector = ptr;

	return &(first_sector[index / HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR]
				 .entries[index % HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR]);
}

static int holepunch_evaluate_at_tag(struct eraser_dev *rd, u64 tag,
									 struct crypto_blkcipher *tfm, u8 *out)
{
	int r;
	struct crypto_blkcipher *this_tfm;

	if (!tfm)
	{
		this_tfm = rd->tfm[get_cpu()];
	}
	else
	{
		this_tfm = tfm;
	}

	r = evaluate_at_tag(&holepunch_get_keynode_by_index, rd->pprf_master_key, rd->hp_h->prg_iv, this_tfm,
						rd->hp_h->pprf_depth, tag, out);
	if (!tfm)
	{
		put_cpu();
	}

	return r;
}

static int holepunch_puncture_at_tag(struct eraser_dev *rd, u64 tag,
									 struct crypto_blkcipher *tfm)
{
	int r;
	struct crypto_blkcipher *this_tfm;

	if (!tfm) {
		this_tfm = rd->tfm[get_cpu()];
	} else {
		this_tfm = tfm;
	}

	r = puncture_at_tag(&holepunch_get_keynode_by_index, rd->pprf_master_key, rd->hp_h->prg_iv, this_tfm,
		rd->hp_h->pprf_depth, &rd->hp_h->master_key_count,
		&rd->pprf_master_key_capacity, tag);
	if (!tfm) {
		put_cpu();
	}

	// If we are at the key limit, synchronously refresh pprf key
	if (rd->hp_h->master_key_count + 2 * rd->hp_h->pprf_depth > rd->hp_h->master_key_limit) {
		holepunch_refresh_pprf_key(rd);
	}

	// Expand the in-memory pprf key buffer if needed.
	if (rd->hp_h->master_key_count + 2 * rd->hp_h->pprf_depth > rd->pprf_master_key_capacity) {
		holepunch_expand_master_key(rd, HOLEPUNCH_PPRF_EXPANSION_FACTOR);
	}
	return r;
}

#ifdef DEBUG
static void holepunch_print_master_key(struct eraser_dev *rd)
{
	print_master_key(&holepunch_get_keynode_by_index,
		rd->pprf_master_key, &rd->hp_h->master_key_count);
}
#endif

/*
 * Crypto functions.
 */

/* Convert one buffer of data. */
static void __eraser_do_crypto(struct scatterlist *src, struct scatterlist *dst, u64 len,
		u8 *key, u8 *iv, struct crypto_blkcipher *tfm,
		int op, struct eraser_dev *rd)
{
	struct blkcipher_desc desc;

	/*
	 * We don't have explcit locks, but per cpu transforms. This means we
	 * would be in trouble if we are converting more than one buffer,
	 * calling this routine repeatedly, and the function gets scheduled on a
	 * different CPU at some point. In that case, pass a separate TFM from
	 * the outside, and per CPU transforms will be ignored.
	 */
	if (tfm)
		desc.tfm = tfm;
	else
		desc.tfm = rd->tfm[get_cpu()];

	desc.flags = 0;
	if (key)
		crypto_blkcipher_setkey(desc.tfm, key, ERASER_KEY_LEN);

	if (iv)
		crypto_blkcipher_set_iv(desc.tfm, iv, ERASER_IV_LEN);

	if (op == ERASER_ENCRYPT)
	{
		if (crypto_blkcipher_encrypt(&desc, dst, src, len))
			DMCRIT("Error doing crypto");
	}
	else if (op == ERASER_DECRYPT)
	{
		if (crypto_blkcipher_decrypt(&desc, dst, src, len))
			DMCRIT("Error doing crypto");
	}
	else
	{
		DMCRIT("Unknown crypto operation");
	}

	if (!tfm)
		put_cpu();
}

/* Convert between two buffers. */
static void eraser_do_crypto_between_buffers(char *from_buf, char *to_buf, u64 len,
											 u8 *key, u8 *iv, struct crypto_blkcipher *tfm,
											 int op, struct eraser_dev *rd)
{
	struct scatterlist src;
	struct scatterlist dst;

	sg_init_table(&src, 1);
	sg_init_table(&dst, 1);

	sg_set_buf(&src, from_buf, len);
	sg_set_buf(&dst, to_buf, len);

	__eraser_do_crypto(&src, &dst, len, key, iv, tfm, op, rd);
}

/* Convert between two pages. */
static void eraser_do_crypto_between_pages(struct page *from, struct page *to, unsigned offset, u64 len,
										   u8 *key, u8 *iv, struct crypto_blkcipher *tfm,
										   int op, struct eraser_dev *rd)
{
	char *from_buf = ((char *)kmap(from)) + offset;
	char *to_buf = ((char *)kmap(to)) + offset;

	eraser_do_crypto_between_buffers(from_buf, to_buf, len, key, iv, tfm, op, rd);

	kunmap(from);
	kunmap(to);
}

/* Convert a data buffer in place. */
static inline void eraser_do_crypto_from_buffer(char *buf, u64 len,
												u8 *key, u8 *iv, struct crypto_blkcipher *tfm,
												int op, struct eraser_dev *rd)
{
	eraser_do_crypto_between_buffers(buf, buf, len, key, iv, tfm, op, rd);
}

/* Convert a page in place. */
static void eraser_do_crypto_from_page(struct page *p, unsigned offset,
									   u64 len, u8 *key, u8 *iv, struct crypto_blkcipher *tfm,
									   int op, struct eraser_dev *rd)
{
	char *buf = ((char *)kmap(p)) + offset;

	eraser_do_crypto_from_buffer(buf, len, key, iv, tfm, op, rd);

	kunmap(p);
}

// Some holepunch stuff

static inline void holepunch_write_header(struct eraser_dev *rd)
{
	eraser_rw_sector(0, WRITE, (char *)rd->hp_h, rd);
}

static inline struct holepunch_header *holepunch_read_header(struct eraser_dev *rd)
{
	return (struct holepunch_header *)eraser_rw_sector(0, READ, NULL, rd);
}

static void holepunch_do_crypto_on_key_table_sector(struct eraser_dev *rd,
													struct holepunch_filekey_sector *sector, u8 *key, u8 *iv, int op)
{
	struct blkcipher_desc desc;
	struct scatterlist src, dst;
	u32 len;

	len = HOLEPUNCH_FILEKEYS_PER_SECTOR * sizeof(struct holepunch_filekey_entry);

	sg_init_table(&src, 1);
	sg_init_table(&dst, 1);
	sg_set_buf(&src, sector->entries, len);
	sg_set_buf(&dst, sector->entries, len);

	// this doesnt work for some reason
	desc.tfm = rd->tfm[get_cpu()];
	// desc.tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	desc.flags = 0;
	if (key)
		crypto_blkcipher_setkey(desc.tfm, key, PRG_INPUT_LEN);
	if (iv)
		crypto_blkcipher_set_iv(desc.tfm, iv, PRG_INPUT_LEN);

	if (op == ERASER_ENCRYPT)
	{
		if (crypto_blkcipher_encrypt(&desc, &dst, &src, len))
			DMCRIT("Error doing crypto");
	}
	else if (op == ERASER_DECRYPT)
	{
		if (crypto_blkcipher_decrypt(&desc, &dst, &src, len))
			DMCRIT("Error doing crypto");
	}
	else
	{
		DMCRIT("Unknown crypto operation");
	}
	// crypto_free_blkcipher(desc.tfm);
	put_cpu();
}

// PPRF key must be loaded in already!

// should probably rewrite this to read sector by sector
static struct holepunch_filekey_sector *holepunch_read_key_table(struct eraser_dev *rd)
{
	char *data;
	struct holepunch_filekey_sector *map;
	unsigned sectorno;
	u8 pprf_out[PRG_INPUT_LEN];
	u8 iv_0[PRG_INPUT_LEN];

	map = vmalloc(ERASER_SECTOR * rd->hp_h->key_table_len);
	if (!map)
		return NULL;
	memset(iv_0, 0, PRG_INPUT_LEN);

	for (sectorno = 0; sectorno < rd->hp_h->key_table_len; ++sectorno)
	{
		data = eraser_rw_sector(sectorno + rd->hp_h->key_table_start,
								READ, NULL, rd);
		memcpy(map + sectorno, data, ERASER_SECTOR);
		eraser_free_sector(data, rd);

		holepunch_evaluate_at_tag(rd, (map + sectorno)->tag, NULL, pprf_out);
		// #ifdef DEBUG
		// 		printk(KERN_INFO "READ TABLE: PPRF output for sector %u, tag %llu: %16ph \n",
		// 			sectorno, (map+sectorno)->tag, pprf_out);
		// #endif
		holepunch_do_crypto_on_key_table_sector(rd, map + sectorno, pprf_out, iv_0, ERASER_DECRYPT);
	}
	return map;
}

static void holepunch_write_key_table_sector(struct eraser_dev *rd, unsigned sectorno)
{
	struct page *p;
	u8 pprf_out[PRG_INPUT_LEN];
	u8 iv_0[PRG_INPUT_LEN];
	struct holepunch_filekey_sector *sector, *data;

	p = eraser_allocate_page(rd);
	data = kmap(p);
	sector = rd->key_table + sectorno;
	memcpy(data, sector, ERASER_SECTOR);
	// #ifdef DEBUG
	// 	printk(KERN_INFO "WRITE TABLE: Evaluating tag %llu for sector %u\n",
	// 		sector->tag, sectorno);
	// #endif
	holepunch_evaluate_at_tag(rd, sector->tag, NULL, pprf_out);
	memset(iv_0, 0, PRG_INPUT_LEN);
#ifdef DEBUG
	printk(KERN_INFO "WRITE TABLE: PPRF output for sector %u, tag %llu: %16ph \n",
		   sectorno, sector->tag, pprf_out);
#endif
	holepunch_do_crypto_on_key_table_sector(rd, data, pprf_out, iv_0, ERASER_ENCRYPT);

	eraser_rw_sector(rd->hp_h->key_table_start + sectorno,
					 WRITE, data, rd);

	kunmap(p);
	eraser_free_page(p, rd);
}

static int holepunch_set_new_tpm_key(struct eraser_dev *rd)
{
	// DMCRIT("Holepunch set new key entry.\n");
	eraser_get_random_bytes_kernel(rd->new_master_key, ERASER_KEY_LEN);
	__set_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status);
	while (eraser_set_master_key(rd))
	{
		// DMCRIT("Holepunch cannot set new TPM key...\n");
		msleep(100);
	}
	msleep(10);
	while (!test_and_clear_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status))
	{
		DMCRIT("Holepunch waiting for new key to be set.");
		wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
	}
	memcpy(rd->master_key, rd->new_master_key, ERASER_KEY_LEN);

	return 0;
}

static inline unsigned holepunch_get_parent_sectorno_for_fkt_bottom_layer(struct eraser_dev *rd, unsigned index)
{
	return (index / HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline struct holepunch_pprf_fkt_entry 
	*holepunch_get_parent_entry_for_fkt_bottom_layer(struct eraser_dev *rd, unsigned index)
{
	return rd->pprf_fkt[holepunch_get_parent_sectorno_for_fkt_bottom_layer(rd, index)].entries
		 + (index % HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static int holepunch_alloc_pprf_fkt(struct eraser_dev *rd)
{
	rd->pprf_fkt = vmalloc(rd->hp_h->pprf_fkt_len * ERASER_SECTOR);
	return 0;
}

static void holepunch_init_pprf_fkt(struct eraser_dev *rd)
{
	u32 i;

	for (i = 0; i < rd->hp_h->pprf_fkt_len; ++i)
	{
#ifdef DEBUG
		memset((rd->pprf_fkt + i)->entries, i,
			   HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR * sizeof(struct holepunch_pprf_fkt_entry));
#else
		eraser_get_random_bytes_kernel((rd->pprf_fkt + i)->entries,
									   HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR * sizeof(struct holepunch_pprf_fkt_entry));
#endif
	}

	// Initialize PPRF FKT IV
#ifdef DEBUG
	memset(rd->hp_h->slot_map_iv, 0xAF, ERASER_IV_LEN);
#else
	eraser_get_random_bytes_kernel(rd->hp_h->slot_map_iv, ERASER_IV_LEN);
#endif
	holepunch_write_header(rd);
}

static void holepunch_write_pprf_fkt_top_sector(struct eraser_dev *rd,
												unsigned sector, struct crypto_blkcipher *tfm, char *map, bool fkt_refresh)
{
	if (fkt_refresh)
	{
		holepunch_set_new_tpm_key(rd);
	}
	memcpy(map, rd->pprf_fkt + (sector), ERASER_SECTOR);
	eraser_do_crypto_from_buffer(map, ERASER_SECTOR, rd->master_key,
								 rd->hp_h->slot_map_iv, tfm, ERASER_ENCRYPT, rd);
	eraser_rw_sector(sector + rd->hp_h->pprf_fkt_start, WRITE, map, rd);
}

static void holepunch_write_pprf_fkt_bottom_sector(struct eraser_dev *rd,
	unsigned sector, struct crypto_blkcipher *tfm, char *map, bool fkt_refresh)
{
	struct holepunch_pprf_fkt_entry *parent;
	printk(KERN_INFO "?\n");
	parent = holepunch_get_parent_entry_for_fkt_bottom_layer(rd, sector);
	memcpy(map, rd->pprf_fkt + sector, ERASER_SECTOR);

	if (fkt_refresh) {
		eraser_get_random_bytes_kernel(parent->key, ERASER_KEY_LEN);
		eraser_get_random_bytes_kernel(parent->iv, ERASER_IV_LEN);
		holepunch_write_pprf_fkt_top_sector(rd,
			holepunch_get_parent_sectorno_for_fkt_bottom_layer(rd, sector),
			tfm, map, fkt_refresh);
	}

	eraser_do_crypto_from_buffer(map, ERASER_SECTOR,
		parent->key, parent->iv, tfm, ERASER_ENCRYPT, rd);
	eraser_rw_sector(sector + rd->hp_h->pprf_fkt_top_width + rd->hp_h->pprf_fkt_start,
		WRITE, map, rd);
}

static int holepunch_write_pprf_fkt(struct eraser_dev *rd)
{
	struct crypto_blkcipher *tfm;
	char *data;
	unsigned sector;

#ifdef DEBUG
	printk(KERN_INFO "Writing PPRF FKT: encrypting wih M = %32ph\n", rd->master_key);
#endif
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	data = kmalloc(ERASER_SECTOR, GFP_KERNEL);
	if (!data)
	{
		DMCRIT("OOM!");
		return -ENOMEM;
	}

	// Encrypt base layer
	for (sector = 0; sector + rd->hp_h->pprf_fkt_top_width < rd->hp_h->pprf_fkt_len; 
		++sector) {
		holepunch_write_pprf_fkt_bottom_sector(rd, sector, tfm, data, false);
	}

	// Encrypt first layer
	for (sector = 0; sector < rd->hp_h->pprf_fkt_top_width; ++sector) {
		holepunch_write_pprf_fkt_top_sector(rd, sector, tfm, data, false);
	}
	crypto_free_blkcipher(tfm);
	kfree(data);
#ifdef DEBUG
	printk(KERN_INFO "PPRF FKT written!\n");
#endif
	return 0;
}

static void holepunch_read_pprf_fkt(struct eraser_dev *rd)
{
	struct crypto_blkcipher *tfm;
	struct holepunch_pprf_fkt_entry *parent;
	char *data;
	unsigned sector;

#ifdef DEBUG
	printk(KERN_INFO "Reading PPRF FKT: decrypting wih M = %32ph\n", rd->master_key);
#endif
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	rd->pprf_fkt = vmalloc(ERASER_SECTOR * rd->hp_h->pprf_fkt_len);
	if (!rd->pprf_fkt)
	{
		return;
	}

	// Decrypt first layer
	for (sector = 0; sector < rd->hp_h->pprf_fkt_top_width; ++sector)
	{
		data = eraser_rw_sector(sector + rd->hp_h->pprf_fkt_start, READ, NULL, rd);
		eraser_do_crypto_from_buffer(data, ERASER_SECTOR, rd->master_key,
									 rd->hp_h->slot_map_iv, tfm, ERASER_DECRYPT, rd);
		memcpy(rd->pprf_fkt + (sector), data, ERASER_SECTOR);
		eraser_free_sector(data, rd);
	}

	// Decrypt base layer
	for (sector = 0; sector + rd->hp_h->pprf_fkt_top_width < rd->hp_h->pprf_fkt_len; ++sector)
	{
		data = eraser_rw_sector(sector + rd->hp_h->pprf_fkt_top_width + rd->hp_h->pprf_fkt_start,
								READ, NULL, rd);
		parent = holepunch_get_parent_entry_for_fkt_bottom_layer(rd, sector);
		eraser_do_crypto_from_buffer(data, ERASER_SECTOR,
									 parent->key, parent->iv, tfm, ERASER_DECRYPT, rd);
		memcpy(rd->pprf_fkt + (sector + rd->hp_h->pprf_fkt_top_width), data, ERASER_SECTOR);
		eraser_free_sector(data, rd);
	}
	crypto_free_blkcipher(tfm);

#ifdef DEBUG
	printk(KERN_INFO "PPRF FKT read!\n");
#endif
}

/* PPRF keynode functions
 * Reading and writing requires the PPRF FKT
 */
static inline unsigned holepunch_get_pprf_fkt_sectorno_for_keynode_sector(struct eraser_dev *rd, unsigned index)
{
	return rd->hp_h->pprf_fkt_top_width + (index / HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline struct holepunch_pprf_fkt_entry *holepunch_get_pprf_fkt_entry_for_keynode_sector(struct eraser_dev *rd, unsigned index)
{
	return rd->pprf_fkt[holepunch_get_pprf_fkt_sectorno_for_keynode_sector(rd, index)].entries + (index % HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline int holepunch_get_pprf_keynode_sector_for_keynode_index(struct eraser_dev *rd,
																	  int pprf_keynode_index)
{
	return pprf_keynode_index / HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR;
}

/* The PPRF FKT needs to be loaded in already */
static struct holepunch_pprf_keynode_sector *holepunch_read_pprf_key(struct eraser_dev *rd)
{
	struct crypto_blkcipher *tfm;
	char *data, *map;
	unsigned sector;
	struct holepunch_pprf_fkt_entry *fkt_entry;

	DMCRIT("NEED TO REWRITE .. ADD IV THING");

	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	map = vmalloc(ERASER_SECTOR * rd->hp_h->pprf_key_len);
	if (!map)
		return NULL;

	for (sector = 0; sector < rd->hp_h->pprf_key_len; ++sector)
	{
		data = eraser_rw_sector(sector + rd->hp_h->pprf_key_start, READ, NULL, rd);
		fkt_entry = holepunch_get_pprf_fkt_entry_for_keynode_sector(rd, sector);
		eraser_do_crypto_from_buffer(data, ERASER_SECTOR, fkt_entry->key,
									 fkt_entry->iv, tfm, ERASER_DECRYPT, rd);
		memcpy(map + (sector * ERASER_SECTOR), data, ERASER_SECTOR);
		eraser_free_sector(data, rd);
	}
	crypto_free_blkcipher(tfm);
	return (struct holepunch_pprf_keynode_sector *)map;
}

/* map and tfm are passed in from the outside */
static int holepunch_write_pprf_key_sector(struct eraser_dev *rd, unsigned sector,
	struct crypto_blkcipher *tfm, char *map, bool fkt_refresh)
{
	struct holepunch_pprf_fkt_entry *fkt_entry;

	fkt_entry = holepunch_get_pprf_fkt_entry_for_keynode_sector(rd, sector);
	if (fkt_refresh) {
		eraser_get_random_bytes_kernel(fkt_entry->key, ERASER_KEY_LEN);
		eraser_get_random_bytes_kernel(fkt_entry->iv, ERASER_IV_LEN);
		holepunch_write_pprf_fkt_bottom_sector(rd,
			holepunch_get_pprf_fkt_sectorno_for_keynode_sector(rd, sector),
			tfm, map, fkt_refresh);
	}
	memcpy(map, rd->pprf_master_key + sector, ERASER_SECTOR);

	eraser_do_crypto_from_buffer(map, ERASER_SECTOR, fkt_entry->key,
		fkt_entry->iv, tfm, ERASER_ENCRYPT, rd);

	eraser_rw_sector(rd->hp_h->pprf_key_start + sector, WRITE, map, rd);
	return 0;
}

static int holepunch_write_pprf_key(struct eraser_dev *rd)
{
	struct crypto_blkcipher *tfm;
	char *map;
	unsigned sector;

	DMCRIT("NEED TO REWRITE");

	map = kmalloc(ERASER_SECTOR, GFP_KERNEL);
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (!map || !tfm)
	{
		DMCRIT("OOM!");
		return -1;
	}

	for (sector = 0;
		 sector < DIV_ROUND_UP(rd->hp_h->master_key_count * sizeof(struct pprf_keynode), ERASER_SECTOR);
		 ++sector) {
		holepunch_write_pprf_key_sector(rd, sector, tfm, map, false);
	}
	crypto_free_blkcipher(tfm);
	kfree(map);

	return 0;
}

// TODO: crash?
static int holepunch_refresh_pprf_key(struct eraser_dev *rd)
{
	int r;
	unsigned index;
	u64 newtag = 0;
	DMCRIT("UNIMPLEMENTED");
	return -1;

	// #ifdef DEBUG
	DMCRIT("\n == REFRESH COMMENCING == \n");
	// #endif

	holepunch_alloc_master_key(rd, HOLEPUNCH_INITIAL_PPRF_SIZE);
	holepunch_init_master_key(rd);
	r = holepunch_write_pprf_key(rd);

	for (index = 0; index < rd->hp_h->key_table_len; ++index)
	{
		rd->key_table[index].tag = newtag;
		holepunch_write_key_table_sector(rd, index);
		++newtag;
	}

	rd->hp_h->tag = newtag;

	holepunch_write_header(rd);

	// #ifdef DEBUG
	DMCRIT("\n == REFRESH COMPLETED == \n");
	// #endif
	return 0;
}


/* Drop a cache entry. Lock from outside. */
static inline void eraser_drop_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd)
{
	list_del(&c->list);
	eraser_free_sector((char *)c->map, rd);
	eraser_free_map_cache(c, rd);
	rd->map_cache_count -= 1;
}

/* Write a cache entry back to disk. Lock from outside. */
static void eraser_write_map_cache(struct eraser_map_cache *c, struct eraser_dev *rd)
{
	char *buf;
	struct page *p;

	p = eraser_allocate_page(rd);
	buf = kmap(p);

	eraser_do_crypto_between_buffers((char *)c->map, buf, ERASER_SECTOR,
									 rd->slot_map[c->slot_no].key, rd->slot_map[c->slot_no].iv,
									 NULL, ERASER_ENCRYPT, rd);
	eraser_rw_sector(rd->rh->inode_map_start + c->slot_no, WRITE, buf, rd);
	c->status &= ~ERASER_CACHE_DIRTY;

	kunmap(p);
	eraser_free_page(p, rd);
}

/* Drops all cache entries, writes them back to disk if dirty. Locked from
 * inside. */
static void eraser_force_evict_map_cache(struct eraser_dev *rd)
{
	struct eraser_map_cache *c;
	struct eraser_map_cache *n;
	int i;

	for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i)
	{
		down(&rd->cache_lock[i]);
		list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list)
		{
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
static int eraser_evict_map_cache(void *data)
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

	while (1)
	{
		/* first_access_timeout = jiffies - ERASER_CACHE_EXP_FIRST_ACCESS; */
		last_access_timeout = jiffies - ERASER_CACHE_EXP_LAST_ACCESS;
		last_dirty_timeout = jiffies - ERASER_CACHE_EXP_LAST_DIRTY;

		for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i)
		{
			down(&rd->cache_lock[i]);
			list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list)
			{

				will_evict = 0;
				will_write_if_dirty = 0;

				if (time_after(last_dirty_timeout, c->last_dirty))
					will_write_if_dirty = 1;

				if (time_after(last_access_timeout, c->last_access))
					will_evict = 1;

				if ((will_write_if_dirty || will_evict) && (c->status & ERASER_CACHE_DIRTY))
				{
					eraser_write_map_cache(c, rd);
				}

				if (will_evict && (rd->map_cache_count > ERASER_CACHE_MEMORY_PRESSURE))
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


static void holepunch_get_key_for_inode(u64 inode_no, u8 *key, u8 *iv, struct eraser_dev *rd)
{
	struct holepunch_filekey_sector *sector;
	int index;

	sector = holepunch_get_fkt_sector_for_inode(rd, inode_no);
	index = holepunch_get_sector_index_for_inode(rd, inode_no);
#ifdef DEBUG
	printk(KERN_INFO "Grabbing key and iv from sector %llu index %u\n",
		   inode_no / HOLEPUNCH_FILEKEYS_PER_SECTOR, index);
#endif
	memcpy(key, sector->entries[index].key, ERASER_KEY_LEN);
	memcpy(iv, sector->entries[index].iv, ERASER_IV_LEN);
}

static inline struct holepunch_filekey_sector *holepunch_get_fkt_sector_for_inode(struct eraser_dev *rd, u64 ino)
{
	return rd->key_table + (ino / HOLEPUNCH_FILEKEYS_PER_SECTOR);
}

static inline int holepunch_get_sector_index_for_inode(struct eraser_dev *rd, u64 ino)
{
	return ino % HOLEPUNCH_FILEKEYS_PER_SECTOR;
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

	while (encrypted_bio->bi_iter.bi_size)
	{
		vec = bio_iter_iovec(encrypted_bio, encrypted_bio->bi_iter);
		bio_advance_iter(encrypted_bio, &encrypted_bio->bi_iter, vec.bv_len);
		eraser_free_page(vec.bv_page, w->rd);
	}

	bio_put(encrypted_bio);
	eraser_free_io_work(w);
}

static void eraser_derive_file_iv(u8 *iv, unsigned long index)
{
	*(unsigned long *)iv |= index;
}

static void eraser_derive_sector_iv(u8 *iv, unsigned long index, struct eraser_dev *rd)
{
	*(unsigned long *)iv = index;

	crypto_cipher_encrypt_one(rd->essiv_tfm[get_cpu()], iv, iv);
	put_cpu();
}

/* Bottom-half entry for write operations. */
static void eraser_do_write_bottomhalf(struct eraser_io_work *w)
{
	struct bio *clone;
	struct bio *encrypted_bio;
	struct bio_vec vec;
	struct page *p;
	u8 key[ERASER_KEY_LEN];
	u8 iv[ERASER_IV_LEN];
	u8 derived_iv[ERASER_IV_LEN];

	if (w->is_file)
	{
		holepunch_get_key_for_inode(
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			key, iv, w->rd);

#ifdef DEBUG
		printk(KERN_INFO "WRITE: Crypto info for inode %lu:\n\t\t key = %32ph\n\t\t iv = %16ph\n",
			   bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			   key, iv);
#endif
	}
	else
	{
		memcpy(key, w->rd->enc_key, ERASER_KEY_LEN);
		memset(iv, 0, ERASER_IV_LEN);
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

		memcpy(derived_iv, iv, ERASER_IV_LEN);
		if (w->is_file)
			eraser_derive_file_iv(derived_iv, vec.bv_page->index);
		else
			eraser_derive_sector_iv(derived_iv, clone->bi_iter.bi_sector, w->rd);

		p = eraser_allocate_page(w->rd);
		eraser_do_crypto_between_pages(vec.bv_page, p, 0, ERASER_SECTOR, key, derived_iv,
									   NULL, ERASER_ENCRYPT, w->rd);
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
	u8 iv[ERASER_IV_LEN];
	u8 derived_iv[ERASER_IV_LEN];

	if (w->is_file)
	{
		holepunch_get_key_for_inode(
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			key, iv, w->rd);
#ifdef DEBUG
		printk(KERN_INFO "READ: Crypto info for inode %lu:\n\t\t key = %32ph\n\t\t iv = %16ph\n",
			   bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			   key, iv);
#endif
	}
	else
	{
		memcpy(key, w->rd->enc_key, ERASER_KEY_LEN);
		memset(iv, 0, ERASER_IV_LEN);
	}

	/* Read is complete at this point. Simply iterate over pages and
	 * decrypt. */
	clone = bio_clone_fast(w->bio, GFP_NOIO, w->rd->bioset);
	while (clone->bi_iter.bi_size)
	{
		vec = bio_iter_iovec(clone, clone->bi_iter);
		bio_advance_iter(clone, &clone->bi_iter, vec.bv_len);

		memcpy(derived_iv, iv, ERASER_IV_LEN);
		if (w->is_file)
			eraser_derive_file_iv(derived_iv, vec.bv_page->index);
		else
			eraser_derive_sector_iv(derived_iv, clone->bi_iter.bi_sector, w->rd);

		eraser_do_crypto_from_page(vec.bv_page, 0, ERASER_SECTOR, key, derived_iv,
								   NULL, ERASER_DECRYPT, w->rd);
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

	// DMCRIT("I/O from PID %i\n", task_pid_nr(current));

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
 * Unlink functions.
 */

/* Randomize key and IV of deleted inode. */
static inline void eraser_refresh_map_entry(struct eraser_map_entry *m, struct eraser_dev *rd)
{
	eraser_get_random_key(m->key, rd);
	eraser_get_random_iv(m->iv, rd);
	m->status |= ERASER_CACHE_DIRTY;
}

/* Bottom half for unlink operations. */
static void holepunch_do_unlink(struct work_struct *work)
{
	DMCRIT("Unlinking from PID %u\n", task_pid_nr(current));
	struct eraser_unlink_work *w = container_of(work, struct eraser_unlink_work, work);
	struct crypto_blkcipher *tfm;
	u64 sectorno, index, old_tag;
	u32 punctured_keynode_index, new_keynode_start_index, new_keynode_end_index;
	u32 punctured_keynode_sector, new_keynode_start_sector, new_keynode_end_sector;
	struct holepunch_filekey_sector *fktsector;
	char *map;

	sectorno = w->inode_no / HOLEPUNCH_FILEKEYS_PER_SECTOR;
	fktsector = holepunch_get_fkt_sector_for_inode(w->rd, w->inode_no);
	index = holepunch_get_sector_index_for_inode(w->rd, w->inode_no);

	/* rerolling the slot */
	// #ifdef DEBUG
	// 	printk(KERN_INFO "Old file key entry\t\t tag: %llu\t\t"
	// 					 "\t\t(plaintext) key : %32ph\n"
	// 					 "\t\t(plaintext) iv : %16ph\n",
	// 					 ,sector->tag, sector->entries[index].key,
	// 					 sector->entries[index].iv);
	// #endif
	eraser_get_random_bytes_kernel(fktsector->entries[index].key, ERASER_KEY_LEN);
	eraser_get_random_bytes_kernel(fktsector->entries[index].iv, ERASER_IV_LEN);
	old_tag = fktsector->tag;
	fktsector->tag = w->rd->hp_h->tag;
	++w->rd->hp_h->tag;
#ifdef DEBUG
	printk(KERN_INFO "Old file key entry\t\t tag: %llu\t\t"
					 "New file key entry\t\t tag: %llu\n",
		   old_tag, fktsector->tag);
	//  "\t\t(plaintext) key : %32ph\n"
	//  "\t\t(plaintext) iv : %16ph\n",
	//  ,sector->tag, sector->entries[index].key,
	//  sector->entries[index].iv);
#endif
	new_keynode_start_index = w->rd->hp_h->master_key_count;
	punctured_keynode_index = holepunch_puncture_at_tag(w->rd, old_tag, NULL);
	new_keynode_end_index = w->rd->hp_h->master_key_count;

	punctured_keynode_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(w->rd, punctured_keynode_index);
	new_keynode_start_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(w->rd, new_keynode_start_index);
	new_keynode_end_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(w->rd, new_keynode_end_index-1);

#ifdef DEBUG
	printk(KERN_INFO "Keylength: %u/%u, limit:%u\n", w->rd->hp_h->master_key_count,
		   w->rd->pprf_master_key_capacity, w->rd->hp_h->master_key_limit);
	printk(KERN_INFO "PPRF keynode indices touched: %lu %lu %lu\n",
		punctured_keynode_index, new_keynode_start_index, new_keynode_end_index);
	printk(KERN_INFO "PPRF keynode sectors touched: %lu %lu %lu\n",
		   punctured_keynode_sector, new_keynode_start_sector, new_keynode_end_sector);
	holepunch_print_master_key(w->rd);
	// printk(KERN_INFO "UNLINK: puncture at tag %llu\n", old_tag);
#endif
	// Persists new crypto information to disk
	DMCRIT("!");
	map = kmalloc(ERASER_SECTOR, GFP_KERNEL);
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (!map || !tfm)
	{
		DMCRIT("Fatal: unlink");
		return;
		// ??
	}

	holepunch_write_pprf_key_sector(w->rd, punctured_keynode_sector, tfm, map, true);
	if (new_keynode_start_sector != punctured_keynode_sector) {
		holepunch_write_pprf_key_sector(w->rd, new_keynode_start_sector, tfm, map, false);
	}
	if (new_keynode_end_sector > new_keynode_start_sector)	{
		holepunch_write_pprf_key_sector(w->rd, new_keynode_end_sector, tfm, map, false);
	}

	holepunch_write_header(w->rd);
	holepunch_write_key_table_sector(w->rd, sectorno);
	// holepunch_write_pprf_key(w->rd);
	eraser_free_unlink_work(w);
}

static void eraser_do_unlink(struct work_struct *work)
{
#ifdef DEBUG
	printk(KERN_INFO "HOLEPUNCH UNLINK\n");
#endif
	holepunch_do_unlink(work);
	// struct eraser_unlink_work *w = container_of(work, struct eraser_unlink_work, work);
	// struct eraser_map_cache *c;
	// u64 slot_no;
	// int bucket;

	// slot_no = eraser_get_slot_no(w->inode_no);
	// bucket = slot_no % ERASER_MAP_CACHE_BUCKETS;

	// down(&w->rd->cache_lock[bucket]);
	// c = eraser_search_map_cache(slot_no, bucket, w->rd);
	// if (!c) {
	// 	c = eraser_cache_map(slot_no, bucket, w->rd);
	// }

	// /* Refresh the inode map key & IV. */
	// eraser_refresh_map_entry(&c->map[eraser_get_inode_offset(w->inode_no)], w->rd);
	// c->status |= ERASER_CACHE_DIRTY;
	// c->last_dirty = jiffies;
	// c->last_access = jiffies;

	// /* Refresh the slot map key & IV as well. */
	// eraser_refresh_map_entry(&w->rd->slot_map[slot_no], w->rd);
	// set_bit(ERASER_KEY_SLOT_MAP_DIRTY, &w->rd->master_key_status);

	// up(&w->rd->cache_lock[bucket]);

	// eraser_free_unlink_work(w);
}

static void eraser_queue_unlink(struct eraser_unlink_work *w)
{
	INIT_WORK(&w->work, eraser_do_unlink);
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
	if (d_is_negative(victim) ||
		(!inode || !inode->i_sb || !inode->i_sb->s_bdev) ||
		victim->d_parent->d_inode != dir ||
		inode_permission(dir, MAY_WRITE | MAY_EXEC) ||
		IS_APPEND(dir) ||
		(check_sticky(dir, inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode) || IS_SWAPFILE(inode)) ||
		d_is_dir(victim) ||
		IS_DEADDIR(dir))
		goto nope;

	/* Queue an unlink work for the proper ERASER instance. */
	list_for_each_entry(rd, &eraser_dev_list, list)
	{
		if (rd->virt_dev == inode->i_sb->s_bdev->bd_dev)
		{
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
static int eraser_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct bio *clone;
	struct eraser_io_work *w;
	struct eraser_dev *rd = (struct eraser_dev *)ti->private;

	if (unlikely(!rd->virt_dev))
		rd->virt_dev = bio->bi_bdev->bd_dev;

	bio->bi_bdev = rd->real_dev->bdev;
	// #ifdef DEBUG
	// 	printk(KERN_INFO "request remapped from sector %u to sector %u\n", bio->bi_iter.bi_sector,
	// 							bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE));
	// #endif
	bio->bi_iter.bi_sector = bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE);

	if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD)))
	{
		return DM_MAPIO_REMAPPED;
	}

	if (bio_has_data(bio))
	{
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
			S_ISREG(bio_iter_iovec(bio, bio->bi_iter).bv_page->mapping->host->i_mode))
		{
			w->is_file = 1; /* We will perform file encryption. */
		}
		else
		{
			w->is_file = 0; /* We will perform good old disk sector encryption. */
		}

		/* We need to perform I/O to read keys, so send to bottom half. */
		if (bio_data_dir(bio) == WRITE)
		{
			bio_get(bio);
			eraser_queue_io(w);
			return DM_MAPIO_SUBMITTED;
		}
		else if (bio_data_dir(bio) == READ)
		{
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
 * Initializers, constructors & destructors.
 */

/* Initializes the AES-CTR context. */
static int eraser_init_rand_context(struct eraser_rand_context *rand)
{
	u8 ctr[16];

	rand->buf = NULL;

	rand->tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (IS_ERR(rand->tfm))
		return ERASER_ERROR;
	/* Key will be set later when filling the buffer. */

	/* Set random counter. */
	eraser_get_random_bytes_kernel(ctr, 16);
	crypto_blkcipher_set_iv(rand->tfm, ctr, 16);

	rand->max_byte = ERASER_PRNG_AESCTR_REFRESH_LEN / ERASER_PRNG_AESCTR_CHUNK_LEN;
	rand->max_chunk = ERASER_PRNG_AESCTR_CHUNK_LEN;

	rand->buf = kmalloc(rand->max_byte, GFP_KERNEL);
	while (!rand->buf)
	{
		DMCRIT("Cannot allocate memory for AES-CTR, %llu bytes", rand->max_byte);

		if (rand->max_byte <= PAGE_SIZE)
		{
			DMCRIT("Bailing out");
			crypto_free_blkcipher(rand->tfm);
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

static void eraser_destroy_rand_context(struct eraser_rand_context *rand)
{
	if (rand->tfm)
		crypto_free_blkcipher(rand->tfm);

	kfree(rand->buf);
}

/* Compute the ESSIV salt from sector encryption key. */
static int eraser_get_essiv_salt(u8 *key, u8 *salt)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int r;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return ERASER_ERROR;

	desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	desc->tfm = tfm;
	desc->flags = 0;

	r = crypto_shash_digest(desc, key, ERASER_KEY_LEN, salt);
	crypto_free_shash(tfm);
	kfree(desc);

	if (r == 0)
		return ERASER_SUCCESS;

	return ERASER_ERROR;
}

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
		DMCRIT("Cannot allocate sk_buff.");

	h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_DIE, 0, GFP_KERNEL);
	if (!h)
		DMCRIT("Cannot put msg.");

	NETLINK_CB(skb_out).dst_group = 0;

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0)
	{
		DMCRIT("Error sending DIE.");
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
		DMCRIT("Cannot allocate sk_buff.");

	h = nlmsg_put(skb_out, 0, 0, ERASER_MSG_GET_KEY, ERASER_MSG_PAYLOAD, GFP_KERNEL);
	if (!h)
		DMCRIT("Cannot put msg.");

	NETLINK_CB(skb_out).dst_group = 0;

	payload = nlmsg_data(h);
	memset(payload, 0, ERASER_MSG_PAYLOAD);
	memcpy(payload, rd->eraser_name, ERASER_NAME_LEN);

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0)
	{
		DMCRIT("Error sending GET KEY.");
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
	eraser_do_crypto_from_page(key_page, 0, ERASER_KEY_LEN,
							   rd->enc_key, iv, NULL, ERASER_ENCRYPT, rd);
	memcpy(payload + ERASER_NAME_LEN, key_buf, ERASER_KEY_LEN);
	kunmap(key_page);
	eraser_free_page(key_page, rd);

	/* Send! */
	if (nlmsg_unicast(eraser_sock, skb_out, rd->helper_pid) != 0)
	{
		DMCRIT("Error sending SET KEY.");
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
	struct page *key_page;
	char *key_buf;
	u8 iv[ERASER_IV_LEN];

	h = (struct nlmsghdr *)skb_in->data;
	payload = nlmsg_data(h);
	len = nlmsg_len(h);

	if (len != ERASER_MSG_PAYLOAD)
	{
		DMCRIT("Unknown message format.");
		return;
	}

	memcpy(name, payload, ERASER_NAME_LEN);
	name[ERASER_NAME_LEN] = '\0';

	found = 0;
	down(&eraser_dev_lock);
	list_for_each_entry(rd, &eraser_dev_list, list)
	{
		if (strcmp(rd->eraser_name, name) == 0)
		{
			found = 1;
			break;
		}
	}
	up(&eraser_dev_lock);

	if (!found)
	{
		DMCRIT("Message to unknown device.");
		return;
	}

	/* Now rd holds our device. */
	if (h->nlmsg_type == ERASER_MSG_GET_KEY)
	{
		/* We got the master key. */
		DMCRIT("Received master key.");
		if (test_and_clear_bit(ERASER_KEY_GET_REQUESTED, &rd->master_key_status))
		{
			memset(iv, 0, ERASER_IV_LEN);

			key_page = eraser_allocate_page(rd);
			key_buf = kmap(key_page);
			memcpy(key_buf, payload + ERASER_NAME_LEN, ERASER_KEY_LEN);
			eraser_do_crypto_from_page(key_page, 0, ERASER_KEY_LEN, rd->enc_key, iv,
									   NULL, ERASER_DECRYPT, rd);
			memcpy(rd->master_key, key_buf, ERASER_KEY_LEN);
			kunmap(key_page);
			eraser_free_page(key_page, rd);

			set_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status);
			complete(&rd->master_key_wait);
		}
		else
		{
			DMCRIT("Received unsolicited key. Dropping.");
		}
	}
	else if (h->nlmsg_type == ERASER_MSG_SET_KEY)
	{
		/* We got confirmation that master key is synched to the vault. */
#ifdef DEBUG
		DMCRIT("Received key sync ACK.");
#endif
		if (test_and_clear_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status))
		{
			set_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status);
			complete(&rd->master_key_wait);
		}
		else
		{
			DMCRIT("Received unsolicited ACK. Dropping.");
		}
	}
	else
	{
		DMCRIT("Unknown message type.");
	}

	/* TODO: Do *we* free the sk_buff here? Somebody please document netlink
	 * properly! */
}

static struct netlink_kernel_cfg eraser_netlink_cfg =
	{
		.input = eraser_netlink_recv,
		.groups = 0,
		.flags = 0,
		.cb_mutex = NULL,
		.bind = NULL,
};

/*
 * Constructor.
 */
static int eraser_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct eraser_dev *rd;
	int helper_pid;
	char dummy;
	int i;
	u8 salt[ERASER_KEY_LEN];

	/*
	 * argv[0]: real block device path
	 * argv[1]: eraser name, NOT path
	 * argv[2]: hex key
	 * argv[3]: virtual device path
	 * argv[4]: helper pid
	 */
	if (argc != 5)
	{
		ti->error = "Invalid argument count.";
		return -EINVAL;
	}

	DMCRIT("Creating ERASER on %s", argv[0]);

	if (sscanf(argv[4], "%d%c", &helper_pid, &dummy) != 1)
	{
		ti->error = "Invalid arguments.";
		return -EINVAL;
	}
	DMCRIT("Helper PID: %d", helper_pid);

	/* Lock everything until we make sure this device is create-able. */
	down(&eraser_dev_lock);

	rd = eraser_lookup_dev(argv[0]);
	if (rd)
	{
		ti->error = "ERASER already running on device.";
		goto lookup_dev_fail;
	}

	rd = eraser_create_dev(ti, argv[0], argv[1]);
	if (!rd)
	{
		ti->error = "Cannot create ERASER on device.";
		goto create_dev_fail;
	}
	up(&eraser_dev_lock);

	rd->helper_pid = helper_pid;

	/* Create memory pools, work queues, locks... */
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
	rd->hp_h = holepunch_read_header(rd);
	if (!rd->hp_h)
	{
		ti->error = "Could not read header.";
		goto read_header_fail;
	}

#ifdef DEBUG
	printk(KERN_INFO "\nKernel-land info:\n");
	printk(KERN_INFO "Key table start: %llu\n", rd->hp_h->key_table_start);
	printk(KERN_INFO "Key table sectors: %llu\n", rd->hp_h->key_table_len);

	printk(KERN_INFO "PPRF fkt start: %llu\n", rd->hp_h->pprf_fkt_start);
	printk(KERN_INFO "PPRF fkt sectors: %llu\n", rd->hp_h->pprf_fkt_len);

	printk(KERN_INFO "PPRF key start: %llu\n", rd->hp_h->pprf_key_start);
	printk(KERN_INFO "PPRF key sectors: %llu\n", rd->hp_h->pprf_key_len);
	printk(KERN_INFO "PPRF key length: %u/%u\n", rd->hp_h->master_key_count, rd->hp_h->master_key_limit);

	printk(KERN_INFO "Data start: %llu\n", rd->hp_h->data_start);
	printk(KERN_INFO "Data sectors: %llu\n", rd->hp_h->data_len);
	printk(KERN_INFO "PRG IV %16ph\n", rd->hp_h->prg_iv);
#endif

	/* We have per-cpu crypto transforms. */
	rd->cpus = num_online_cpus();

	rd->rand = kmalloc(rd->cpus * sizeof(struct eraser_rand_context), GFP_KERNEL);
	for (i = 0; i < rd->cpus; ++i)
	{
		if (eraser_init_rand_context(&rd->rand[i]) == ERASER_ERROR)
		{
			ti->error = "Could not create random context.";
			goto init_rand_context_fail;
		}
	}

	/* Decode disk encryption key. */
	rd->enc_key = eraser_hex_decode(argv[2]);
	/* We don't need the key argument anymore, wipe it clean. */
	memset(argv[2], 0, strlen(argv[2]));

	rd->tfm = kmalloc(rd->cpus * sizeof(struct crypto_blkcipher *), GFP_KERNEL);
	for (i = 0; i < rd->cpus; ++i)
	{
		rd->tfm[i] = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
		if (IS_ERR(rd->tfm[i]))
		{
			ti->error = "Could not create crypto transform.";
			goto init_tfm_fail;
		}
	}

	/* ESSIV crypto transforms. */
	if (eraser_get_essiv_salt(rd->enc_key, salt) != ERASER_SUCCESS)
	{
		DMCRIT("SALT FAIL");
		ti->error = "Could not compute essiv salt.";
		goto compute_essiv_salt_fail;
	}

	rd->essiv_tfm = kmalloc(rd->cpus * sizeof(struct crypto_cipher *), GFP_KERNEL);
	for (i = 0; i < rd->cpus; ++i)
	{
		rd->essiv_tfm[i] = crypto_alloc_cipher("aes", 0, 0);
		if (IS_ERR(rd->essiv_tfm[i]))
		{
			ti->error = "Could not create essiv crypto transform.";
			goto init_essiv_fail;
		}
		crypto_cipher_setkey(rd->essiv_tfm[i], salt, ERASER_KEY_LEN);
	}

	/* Work caches and queues. */
	rd->_io_work_pool = KMEM_CACHE(eraser_io_work, 0);
	if (!rd->_io_work_pool)
	{
		ti->error = "Could not create io cache.";
		goto create_io_cache_fail;
	}

	rd->io_work_pool = mempool_create_slab_pool(ERASER_IO_WORK_POOL_SIZE, rd->_io_work_pool);
	if (!rd->io_work_pool)
	{
		ti->error = "Could not create io pool.";
		goto create_io_pool_fail;
	}

	rd->io_queue = create_workqueue("eraser_io");
	if (!rd->io_queue)
	{
		ti->error = "Could not create io queue.";
		goto create_io_queue_fail;
	}

	rd->_unlink_work_pool = KMEM_CACHE(eraser_unlink_work, 0);
	if (!rd->_unlink_work_pool)
	{
		ti->error = "Could not create unlink cache.";
		goto create_unlink_cache_fail;
	}

	rd->unlink_work_pool = mempool_create_slab_pool(ERASER_UNLINK_WORK_POOL_SIZE, rd->_unlink_work_pool);
	if (!rd->unlink_work_pool)
	{
		ti->error = "Could not create unlink pool.";
		goto create_unlink_pool_fail;
	}

	rd->unlink_queue = create_workqueue("eraser_unlink");
	if (!rd->unlink_queue)
	{
		ti->error = "Could not create unlink queue.";
		goto create_unlink_queue_fail;
	}

	rd->_map_cache_pool = KMEM_CACHE(eraser_map_cache, 0);
	if (!rd->_map_cache_pool)
	{
		ti->error = "Could not create map cache.";
		goto create_map_cache_cache_fail;
	}

	rd->map_cache_pool = mempool_create_slab_pool(ERASER_MAP_CACHE_POOL_SIZE, rd->_map_cache_pool);
	if (!rd->map_cache_pool)
	{
		ti->error = "Could not create map cache pool.";
		goto create_map_cache_pool_fail;
	}

	for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i)
	{
		INIT_LIST_HEAD(&rd->map_cache_list[i]);
		sema_init(&rd->cache_lock[i], 1);
	}

	rd->map_cache_count = 0;

	/* Time to get the master key. */
	init_completion(&rd->master_key_wait);
	rd->master_key_status = 0;
	__set_bit(ERASER_KEY_GET_REQUESTED, &rd->master_key_status);
	while (eraser_get_master_key(rd) != ERASER_SUCCESS)
	{
		DMCRIT("Cannot send GET master key. Will retry.");
		msleep(3000);
	}
	while (!test_bit(ERASER_KEY_GOT_KEY, &rd->master_key_status))
	{
		DMCRIT("Waiting for master key.");
		wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
	}

	/* Read slot map from disk. */
	// rd->slot_map = eraser_read_slot_map(rd->rh->slot_map_start, rd->rh->slot_map_len,
	// 				rd->master_key, rd->rh->slot_map_iv, rd);
	// if (!rd->slot_map) {
	// 	ti->error = "Could not read slot map.";
	// 	goto read_slot_map_fail;
	// }

	if (unlikely(rd->hp_h->master_key_count == 0))
	{
#ifdef DEBUG
		printk(KERN_INFO "Fresh holepunch: generating root pprf key\n");
#endif
		holepunch_alloc_pprf_fkt(rd);
		if (!rd->pprf_fkt)
		{
			ti->error = "Could not allocate pprf fkt.";
			goto read_slot_map_fail;
		}
		holepunch_init_pprf_fkt(rd);
		holepunch_write_pprf_fkt(rd);

		holepunch_alloc_master_key(rd, HOLEPUNCH_INITIAL_PPRF_SIZE);
		if (!rd->pprf_master_key)
		{
			ti->error = "Could not allocate pprf key.";
			goto read_slot_map_fail;
		}
		holepunch_init_master_key(rd);
		holepunch_write_pprf_key(rd);
	}
	else
	{
#ifdef DEBUG
		printk(KERN_INFO "Retrieving pprf key\n");
#endif
		holepunch_read_pprf_fkt(rd);
		if (!rd->pprf_fkt)
		{
			ti->error = "Could not read pprf fkt.";
			goto read_slot_map_fail;
		}
		rd->pprf_master_key = holepunch_read_pprf_key(rd);
		if (!rd->pprf_master_key)
		{
			ti->error = "Could not read pprf key.";
			goto read_slot_map_fail;
		}
	}
#ifdef DEBUG
	holepunch_print_master_key(rd);
#endif

	rd->key_table = holepunch_read_key_table(rd);
	if (!rd->key_table)
	{
		ti->error = "Could not read key table.";
		goto read_slot_map_fail;
	}
#ifdef DEBUG
	printk(KERN_INFO "tag: %llu\nkey: %32ph\niv: %16ph\n",
		   (rd->key_table)[0].tag,
		   (rd->key_table)[0].entries[0].key,
		   (rd->key_table)[0].entries[0].iv);
#endif

	// rd->evict_map_cache_thread = kthread_run(&eraser_evict_map_cache, rd, "eraser_evict");
	// if (IS_ERR(rd->evict_map_cache_thread)) {
	// 	ti->error = "Could not create cache evict thread.";
	// 	goto create_evict_thread_fail;
	// }

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
init_tfm_fail:
	/* We may have created some of the tfms. */
	for (i = i - 1; i >= 0; --i)
		crypto_free_blkcipher(rd->tfm[i]);
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
	bioset_free(rd->bioset);
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
static void eraser_dtr(struct dm_target *ti)
{
	struct eraser_dev *rd = (struct eraser_dev *)ti->private;
	unsigned i;

	DMCRIT("Destroying.");

	kfree(rd->real_dev_path);
	kfree(rd->virt_dev_path);

	/* Stop auto eviction and write back cached maps. */
	// kthread_stop(rd->evict_map_cache_thread);

	// eraser_force_evict_map_cache(rd);

	/* Push master key! */ /* TODO: Add the simple logic to delay key sync
							* here. Just use old key, set a flag in the
							* header. */
	if (test_bit(ERASER_KEY_SLOT_MAP_DIRTY, &rd->master_key_status))
	{
		printk(KERN_INFO "Why is the slot map dirty??\n");
		eraser_get_random_key(rd->new_master_key, rd);
		__set_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status);
		while (eraser_set_master_key(rd) != ERASER_SUCCESS)
		{
			DMCRIT("Cannot send SET master key. Will retry.");
			msleep(3000);
		}

		while (!test_and_clear_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status))
		{
			DMCRIT("Waiting for new key to be set.");
			wait_for_completion_timeout(&rd->master_key_wait, 3 * HZ);
		}
		DMCRIT("New key set.");
		memcpy(rd->master_key, rd->new_master_key, ERASER_KEY_LEN);
	}

	/* Write back slot map. New master key was made ready above. */
	// if (__test_and_clear_bit(ERASER_KEY_SLOT_MAP_DIRTY, &rd->master_key_status)) {
	// 	DMCRIT("Writing slot map");
	// 	eraser_get_random_iv(rd->rh->slot_map_iv, rd);
	// 	eraser_write_slot_map(rd->slot_map, rd->rh->slot_map_start, rd->rh->slot_map_len,
	// 			rd->master_key, rd->rh->slot_map_iv, rd);
	// }
	// vfree(rd->slot_map);

	/* Keys no longer needed, wipe them. */
	holepunch_write_pprf_key(rd);
	eraser_kill_helper(rd);
	memset(rd->new_master_key, 0, ERASER_KEY_LEN);
	memset(rd->master_key, 0, ERASER_KEY_LEN);
	memset(rd->enc_key, 0, ERASER_KEY_LEN);

	/* Write header. */
	holepunch_write_header(rd);
	eraser_free_sector(rd->hp_h, rd);
	// eraser_write_header(rd->rh, rd);
	// eraser_free_sector(rd->rh, rd);

	vfree(rd->pprf_master_key);
	vfree(rd->key_table);

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
		crypto_free_blkcipher(rd->tfm[i]);

	kfree(rd->tfm);

	for (i = 0; i < rd->cpus; ++i)
		eraser_destroy_rand_context(&rd->rand[i]);

	kfree(rd->rand);

	mempool_destroy(rd->page_pool);
	bioset_free(rd->bioset);

	down(&eraser_dev_lock);
	eraser_destroy_dev(ti, rd);
	up(&eraser_dev_lock);

	DMCRIT("Success.");
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
	/* .status = eraser_status, */
	/* .ioctl  = eraser_ioctl, */
	.io_hints = eraser_io_hints,
};

/* Module entry. */
static int __init dm_eraser_init(void)
{
	int r;

	sg_init_one(&sg_in, aes_input, 2 * PRG_INPUT_LEN);
	eraser_sock = netlink_kernel_create(&init_net, ERASER_NETLINK, &eraser_netlink_cfg);
	if (!eraser_sock)
	{
		DMERR("Netlink setup failed.");
		return -1;
	}

	r = register_kprobe(&eraser_unlink_kprobe);
	if (r < 0)
	{
		DMERR("Register kprobe failed %d", r);
		return -1;
	}

	r = dm_register_target(&eraser_target);
	if (r < 0)
		DMERR("dm_register failed %d", r);

	if (!proc_create(ERASER_PROC_FILE, 0, NULL, &eraser_fops))
	{
		DMERR("Cannot create proc file.");
		return -ENOMEM;
	}

	DMCRIT("HOLEPUNCH loaded.");
#ifdef DEBUG
	DMCRIT("Compiled in DEBUG mode.");
	DMCRIT("HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR: %lu", HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR);
	DMCRIT("HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR: %lu", HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
	DMCRIT("HOLEPUNCH_FILEKEYS_PER_SECTOR: %lu", HOLEPUNCH_FILEKEYS_PER_SECTOR);
	// DMCRIT("SIZEOF holepunch_pprf_keynode_sector: %lu", sizeof(struct holepunch_pprf_keynode_sector));
#endif
	return r;
}

/* Module exit. */
static void __exit dm_eraser_exit(void)
{
	remove_proc_entry(ERASER_PROC_FILE, NULL);
	dm_unregister_target(&eraser_target);
	unregister_kprobe(&eraser_unlink_kprobe);
	netlink_kernel_release(eraser_sock);
	DMCRIT("ERASER unloaded.");
}

module_init(dm_eraser_init);
module_exit(dm_eraser_exit);
