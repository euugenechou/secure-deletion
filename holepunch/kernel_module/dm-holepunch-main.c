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

static struct eraser_unlink_work *eraser_allocate_unlink_work(unsigned long inode_no, struct eraser_dev *rd)
{
	struct eraser_unlink_work *w;

	w = mempool_alloc(rd->unlink_work_pool, GFP_ATOMIC);
	if (!w)	{
		DMWARN("Cannot allocate new unlink work!");
	} else {
		w->inode_no = inode_no;
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

static int holepunch_alloc_master_key(struct eraser_dev *rd, unsigned size,
		unsigned mode)
{
	if (mode == HOLEPUNCH_PPRF_NORMAL)
		return alloc_master_key(&rd->pprf_master_key, 
			&rd->pprf_master_key_capacity, size);
	else if (mode == HOLEPUNCH_PPRF_REFRESH)
		return alloc_master_key(&rd->new_pprf_master_key, 
			&rd->new_pprf_master_key_capacity, size);
	else return -1;
}

static int holepunch_expand_master_key(struct eraser_dev *rd, unsigned factor)
{
	return expand_master_key(&rd->pprf_master_key, &rd->pprf_master_key_capacity, factor);
}

static void holepunch_init_master_key(struct eraser_dev *rd, unsigned mode)
{
	if (mode == HOLEPUNCH_PPRF_NORMAL) {
		init_master_key(rd->pprf_master_key, &rd->hp_h->master_key_count,
			ERASER_SECTOR);
	} else if (mode == HOLEPUNCH_PPRF_REFRESH) {
		init_master_key(rd->new_pprf_master_key, NULL, ERASER_SECTOR);
	}
}

// for sanity's sake we assume that the first node is the first array entry
// struct pprf_keynode *holepunch_get_keynode_by_index(void *ptr, unsigned index)
// {
// 	struct holepunch_pprf_keynode_sector *first_sector = ptr;

// 	return &(first_sector[index / HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR]
// 				 .entries[index % HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR]);
// }

/* Read lock PPRF outside */
static int holepunch_evaluate_at_tag(struct eraser_dev *rd, u64 tag,
		u8 *out, struct pprf_keynode *pprf)
{
	int r = evaluate_at_tag(pprf ? pprf : rd->pprf_master_key,
		rd->hp_h->pprf_depth, holepunch_prg_generic, rd, tag, out);
	++rd->stats_evaluate;
	return r;
}


/* PPRF write should be locked from outside */
static int holepunch_puncture_at_tag(struct eraser_dev *rd, u64 tag,
		u32 *punct, u32 *start, u32 *end)
{
	*start = rd->hp_h->master_key_count;
	*punct = puncture_at_tag(rd->pprf_master_key, rd->hp_h->pprf_depth,
		holepunch_prg_generic, rd, &rd->hp_h->master_key_count,
		&rd->pprf_master_key_capacity, tag);
	*end = rd->hp_h->master_key_count;

	// Expand the in-memory pprf key buffer if needed.
	if (rd->hp_h->master_key_count + 2 * rd->hp_h->pprf_depth > rd->pprf_master_key_capacity) {
		holepunch_expand_master_key(rd, HOLEPUNCH_PPRF_EXPANSION_FACTOR);
	}
	++rd->stats_puncture;
	return 0;
}

#ifdef HOLEPUNCH_DEBUG
static void holepunch_print_master_key(struct eraser_dev *rd) {
	print_master_key(rd->pprf_master_key, &rd->hp_h->master_key_count);
}
#endif

/*
 * Crypto functions.
 */

/*
 * The transform tfm should already be initialized (with key and IV); mostly a
 * convenience function to avoid scatterlists.
*/
static void __holepunch_crypto(void *dst, void *src, u64 len, int op,
		struct crypto_blkcipher *tfm)
{
	struct scatterlist sg_src;
	struct scatterlist sg_dst;
	struct blkcipher_desc d;

	sg_init_one(&sg_src, src, len);
	sg_init_one(&sg_dst, dst, len);

	d.tfm = tfm;
	d.flags = 0;

	if (op == ERASER_ENCRYPT) {
		if (crypto_blkcipher_encrypt(&d, &sg_dst, &sg_src, len))
			DMERR("Error encrypting");
	} else if (op == ERASER_DECRYPT) {
		if (crypto_blkcipher_decrypt(&d, &sg_dst, &sg_src, len))
			DMERR("Error decrypting");
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
	__holepunch_crypto(dst, src, len, op, tfm);
	put_cpu();
}

/* Do AES-CBC between two buffers, using the per-cpu transforms. */
static void holepunch_cbc(struct eraser_dev *rd, void *dst, void *src, u64 len,
		int op, u8 *key, u8 *iv)
{
	struct crypto_blkcipher *tfm = rd->cbc_tfm[get_cpu()];
	crypto_blkcipher_setkey(tfm, key, ERASER_KEY_LEN);
	crypto_blkcipher_set_iv(tfm, iv, ERASER_IV_LEN);
	__holepunch_crypto(dst, src, len, op, tfm);
	put_cpu();
}

/* Generate the IV for a sector. */
static void holepunch_gen_iv(struct eraser_dev *rd, u8 *iv, u64 sector)
{
	u8 input[ERASER_IV_LEN] = {0};
	*(u64 *) input = sector;
	holepunch_ecb(rd, iv, input, ERASER_IV_LEN, ERASER_ENCRYPT, rd->iv_key);
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

/* Perform AES-CBC in-place for a file key sector. */
static void holepunch_cbc_filekey_sector(struct eraser_dev *rd,
		struct holepunch_filekey_sector *sector, int op, u8 *key, u64 sectorno)
{
	void *buf;
	u8 iv[ERASER_IV_LEN] = {0};
	holepunch_gen_iv(rd, iv, sectorno);
	/* Exclude the tag, but include the magic bytes. */
	buf = ((char *) sector) + 8;
	holepunch_cbc(rd, buf, buf, ERASER_SECTOR - 8, op, key, iv);
}

/*
 * Create a PRG from AES-ECB for the PPRF; input assumed to be ERASER_KEY_LEN
 * and output assumed to be ERASER_KEY_LEN * 2.
 */
static inline void holepunch_prg(struct eraser_dev *rd, u8 *input, u8 *output)
{
	holepunch_ecb(rd, output, rd->prg_input, ERASER_KEY_LEN * 2, ERASER_ENCRYPT, input);
}

void holepunch_prg_generic(void *v, u8 *input, u8 *output)
{
	holepunch_prg(v, input, output);
}

static void holepunch_write_header(struct eraser_dev *rd)
{
	holepunch_ecb(rd, rd->hp_h->iv_key, rd->iv_key, ERASER_KEY_LEN,
		ERASER_ENCRYPT, rd->master_key);
	eraser_rw_sector(0, WRITE, (char *)rd->hp_h, rd);
}

static void holepunch_read_header(struct eraser_dev *rd)
{
	rd->hp_h = eraser_rw_sector(0, READ, NULL, rd);
	holepunch_ecb(rd, rd->iv_key, rd->hp_h->iv_key, ERASER_KEY_LEN,
		ERASER_DECRYPT, rd->master_key);
}

/* Lock PPRF here */
static struct holepunch_filekey_sector *__holepunch_read_key_table_sector(
		struct eraser_dev *rd, u64 index)
{
	struct holepunch_filekey_sector *data;
	u8 key[PRG_INPUT_LEN];
	u64 sectorno = rd->hp_h->key_table_start + index;
	data = eraser_rw_sector(sectorno, READ, NULL, rd);

	HP_DOWN_READ(&rd->pprf_sem, "PPRF: read sector");
	holepunch_evaluate_at_tag(rd, data->tag, key, NULL);
	HP_UP_READ(&rd->pprf_sem, "PPRF: read sector");
	// #ifdef HOLEPUNCH_DEBUG
	// 		DMINFO("READ TABLE: PPRF output for sector %u, tag %llu: %32ph \n",
	// 			sectorno, (map+sectorno)->tag, pprf_out);
	// #endif
	holepunch_cbc_filekey_sector(rd, data, ERASER_DECRYPT, key, sectorno);

	return data;
}


/* PPRF lock held here
 * mode = HOLEPUNCH_PPRF_NORMAL to use main master key
 * mode = HOLEPUNCH_PPRF_REFRESH to use temp key (only in refresh op) */
static void __holepunch_write_key_table_sector(struct eraser_dev *rd,
		struct holepunch_filekey_sector *sector, u64 index,
		unsigned mode)
{
	struct page *p;
	u8 pprf_out[PRG_INPUT_LEN];
	struct holepunch_filekey_sector *data;
	struct pprf_keynode *pprf;
	u64 sectorno = rd->hp_h->key_table_start + index;

	if (likely(mode == HOLEPUNCH_PPRF_NORMAL))
		pprf = rd->pprf_master_key;
	else if (mode == HOLEPUNCH_PPRF_REFRESH)
		pprf = rd->new_pprf_master_key;

	p = eraser_allocate_page(rd);
	data = kmap(p);
	memcpy(data, sector, ERASER_SECTOR);
	HP_DOWN_READ(&rd->pprf_sem, "PPRF: write sector");
	holepunch_evaluate_at_tag(rd, sector->tag, pprf_out, pprf);
	HP_UP_READ(&rd->pprf_sem, "PPRF: write sector");
	holepunch_cbc_filekey_sector(rd, data, ERASER_ENCRYPT, pprf_out, sectorno);
	// TODO Journal here (part of a larger whole)
	eraser_rw_sector(sectorno, WRITE, data, rd);

	kunmap(p);
	eraser_free_page(p, rd);
}

// TODO Journal here
static int holepunch_set_new_tpm_key(struct eraser_dev *rd)
{
	// DMINFO("Holepunch set new key entry.\n");
	kernel_random(rd->new_master_key, ERASER_KEY_LEN);
	__set_bit(ERASER_KEY_SET_REQUESTED, &rd->master_key_status);
	while (eraser_set_master_key(rd)) {
		// DMINFO("Holepunch cannot set new TPM key...\n");
		msleep(100);
	}
	msleep(10);
	while (!test_and_clear_bit(ERASER_KEY_READY_TO_REFRESH, &rd->master_key_status)) {
#ifdef HOLEPUNCH_DEBUG
		DMINFO("Holepunch waiting for new key to be set.");
#endif
		wait_for_completion_timeout(&rd->master_key_wait, 1 * HZ);
	}
	memcpy(rd->master_key, rd->new_master_key, ERASER_KEY_LEN);
// #ifdef HOLEPUNCH_DEBUG
// 	DMINFO("New TPM key: %32ph\n", rd->master_key);
// #endif
	return 0;
}

static inline unsigned holepunch_get_parent_sectorno_for_fkt_bottom_layer(struct eraser_dev *rd, unsigned index)
{
	return ((index) / HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline unsigned holepunch_get_parent_index_for_fkt_bottom_layer(struct eraser_dev *rd, unsigned index)
{
	return ((index) % HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline struct holepunch_key
		*holepunch_get_parent_entry_for_fkt_bottom_layer(struct eraser_dev *rd, unsigned index)
{
	return rd->pprf_fkt[holepunch_get_parent_sectorno_for_fkt_bottom_layer(rd, index)].entries
		 + holepunch_get_parent_index_for_fkt_bottom_layer(rd, index);
}

// TODO put this in constructor
static int holepunch_alloc_pprf_fkt(struct eraser_dev *rd)
{
	rd->pprf_fkt = vmalloc((rd->hp_h->pprf_key_start - rd->hp_h->pprf_fkt_start) * ERASER_SECTOR);
	return 0;
}

static void holepunch_init_pprf_fkt(struct eraser_dev *rd)
{
	u32 i;

	for (i = 0; i < (rd->hp_h->pprf_key_start - rd->hp_h->pprf_fkt_start); ++i) {
#ifdef HOLEPUNCH_DEBUG
		memset((rd->pprf_fkt + i)->entries, i, ERASER_SECTOR);
#else
		kernel_random((char *) (rd->pprf_fkt + i)->entries, ERASER_SECTOR);
#endif
	}
}

/* Does not write to disk */
// TODO Journaling needed here too (maybe condense functions as well)
static int holepunch_refresh_pprf_fkt(struct eraser_dev *rd, 
		unsigned bot_sect_start, unsigned bot_sect_end)
{
	unsigned i, minp, maxp;
	struct holepunch_key *parent;
	struct page *p;
	char *map;

	p = eraser_allocate_page(rd);
	map = kmap(p);

	minp = holepunch_get_parent_index_for_fkt_bottom_layer(rd, bot_sect_start);
	maxp = holepunch_get_parent_index_for_fkt_bottom_layer(rd, bot_sect_end);

	for (i = bot_sect_start; i < bot_sect_end; ++i) {
		kernel_random((char *) rd->pprf_fkt[i].entries, ERASER_SECTOR);
		parent = holepunch_get_parent_entry_for_fkt_bottom_layer(rd, i);
		kernel_random((char *) parent, ERASER_KEY_LEN);
	}
	kunmap(p);
	eraser_free_page(p, rd);

	return 0;
}

// TODO Journal these next three functions
static void holepunch_write_pprf_fkt_top_sector(struct eraser_dev *rd,
		unsigned sector, char *map, bool fkt_refresh)
{
	if (fkt_refresh) {
		holepunch_set_new_tpm_key(rd);
	}
	memcpy(map, rd->pprf_fkt + sector, ERASER_SECTOR);
	holepunch_cbc_sector_inplace(rd, map, ERASER_ENCRYPT, rd->master_key,
		rd->hp_h->pprf_fkt_start + sector);
	eraser_rw_sector(sector + rd->hp_h->pprf_fkt_start, WRITE, map, rd);
}


static void holepunch_write_pprf_fkt_bottom_sector(struct eraser_dev *rd,
		unsigned sector, char *map, bool fkt_refresh)
{
	struct holepunch_key *parent;
	u64 sectorno;

	parent = holepunch_get_parent_entry_for_fkt_bottom_layer(rd, sector);
	if (fkt_refresh) {
		kernel_random((char *) parent, ERASER_KEY_LEN);

		holepunch_write_pprf_fkt_top_sector(rd,
			holepunch_get_parent_sectorno_for_fkt_bottom_layer(rd, sector),
			map, fkt_refresh);
	}

	sectorno = rd->hp_h->pprf_fkt_start + rd->hp_h->pprf_fkt_top_width + sector;
	holepunch_cbc_sector(rd, map, rd->pprf_fkt + rd->hp_h->pprf_fkt_top_width + sector,
		ERASER_ENCRYPT, parent->key, sectorno);
	eraser_rw_sector(sectorno, WRITE, map, rd);
}

static int holepunch_write_pprf_fkt(struct eraser_dev *rd)
{
	struct page *p;
	char *data;
	unsigned sector;

#ifdef HOLEPUNCH_DEBUG
	DMINFO("Writing PPRF FKT: encrypting wih M = %32ph\n", rd->master_key);
#endif
	p = eraser_allocate_page(rd);
	data = kmap(p);
	// Encrypt base layer
	for (sector = 0; sector < rd->hp_h->pprf_fkt_bottom_width; ++sector) {
		holepunch_write_pprf_fkt_bottom_sector(rd, sector, data, false);
	}

	// Encrypt first layer
	for (sector = 0; sector < rd->hp_h->pprf_fkt_top_width; ++sector) {
		holepunch_write_pprf_fkt_top_sector(rd, sector, data, false);
	}
	kunmap(p);
	eraser_free_page(p, rd);

#ifdef HOLEPUNCH_DEBUG
	DMINFO("PPRF FKT written!\n");
#endif
	return 0;
}

static void holepunch_read_pprf_fkt(struct eraser_dev *rd)
{
	struct holepunch_key *parent;
	char *data;
	u64 index, sectorno;

#ifdef HOLEPUNCH_DEBUG
	DMINFO("Reading PPRF FKT: decrypting wih M = %32ph\n", rd->master_key);
#endif
	rd->pprf_fkt = vmalloc(ERASER_SECTOR * (rd->hp_h->pprf_key_start - rd->hp_h->pprf_fkt_start));
	if (!rd->pprf_fkt) {
		return;
	}

	// Decrypt first layer
	for (index = 0; index < rd->hp_h->pprf_fkt_top_width; ++index) {
		sectorno = rd->hp_h->pprf_fkt_start + index;
		data = eraser_rw_sector(sectorno, READ, NULL, rd);
		holepunch_cbc_sector(rd, rd->pprf_fkt + index, data, ERASER_DECRYPT,
			rd->master_key, sectorno);
		eraser_free_sector(data, rd);
	}

	// Decrypt base layer
	for (index = 0; index < rd->hp_h->pprf_fkt_bottom_width; ++index) {
		// DMINFO("LOADING BOTTOM SECTOR %u\n", index);
		sectorno = rd->hp_h->pprf_fkt_start + rd->hp_h->pprf_fkt_top_width + index;
		data = eraser_rw_sector(sectorno, READ, NULL, rd);
		parent = holepunch_get_parent_entry_for_fkt_bottom_layer(rd, index);
		holepunch_cbc_sector(rd, rd->pprf_fkt + rd->hp_h->pprf_fkt_top_width + index,
			data, ERASER_DECRYPT, parent->key, sectorno);
		eraser_free_sector(data, rd);
	}

#ifdef HOLEPUNCH_DEBUG
	DMINFO("PPRF FKT read!\n");
#endif
}

/* PPRF keynode functions
 * Reading and writing requires the PPRF FKT
 */
static inline unsigned holepunch_get_pprf_fkt_sectorno_for_keynode_sector
		(struct eraser_dev *rd, unsigned index)
{
	return (index / HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline struct holepunch_key *holepunch_get_pprf_fkt_entry_for_keynode_sector
		(struct eraser_dev *rd, unsigned index)
{
	return rd->pprf_fkt[rd->hp_h->pprf_fkt_top_width + 
		holepunch_get_pprf_fkt_sectorno_for_keynode_sector(rd, index)].entries 
		+ (index % HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
}

static inline int holepunch_get_pprf_keynode_sector_for_keynode_index(struct eraser_dev *rd,
		int pprf_keynode_index)
{
	return pprf_keynode_index / HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR;
}

/* The PPRF FKT needs to be loaded in already */
static struct pprf_keynode *holepunch_read_pprf_key(struct eraser_dev *rd)
{
	char *data, *map;
	unsigned sector;
	struct holepunch_key *fkt_entry;
	unsigned data_per_block = sizeof(struct pprf_keynode) 
		* HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR;

	map = vmalloc(2*round_up((rd->hp_h->master_key_count)*sizeof(struct pprf_keynode),
		data_per_block));
	if (!map)
		return NULL;

	for (sector = 0; sector < DIV_ROUND_UP(rd->hp_h->master_key_count, 
			HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR); ++sector)	{
		data = eraser_rw_sector(sector + rd->hp_h->pprf_key_start, READ, NULL, rd);
		fkt_entry = holepunch_get_pprf_fkt_entry_for_keynode_sector(rd, sector);
		holepunch_cbc_sector_inplace(rd, data, ERASER_DECRYPT, fkt_entry->key,
			rd->hp_h->pprf_key_start + sector);
		memcpy(map + (sector * data_per_block), data, data_per_block);
		eraser_free_sector(data, rd);
	}
	return (struct pprf_keynode *)map;
}

// TODO Journal here
/* map and tfm are passed in from the outside */
static int holepunch_write_pprf_key_sector(struct eraser_dev *rd, unsigned index,
	char *map, bool fkt_refresh)
{
	struct holepunch_key *fkt_entry;
	struct holepunch_pprf_keynode_sector *sector = 
		(struct holepunch_pprf_keynode_sector *) map;
	fkt_entry = holepunch_get_pprf_fkt_entry_for_keynode_sector(rd, index);
	if (fkt_refresh) {
		kernel_random((char *) fkt_entry, ERASER_KEY_LEN);
		holepunch_write_pprf_fkt_bottom_sector(rd,
			holepunch_get_pprf_fkt_sectorno_for_keynode_sector(rd, index),
			map, fkt_refresh);
	}
	memcpy(sector->entries, rd->pprf_master_key + index*HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR, 
		sizeof(struct pprf_keynode) * HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR);

	holepunch_cbc_sector_inplace(rd, map, ERASER_ENCRYPT, fkt_entry->key,
		rd->hp_h->pprf_key_start + index);
	eraser_rw_sector(rd->hp_h->pprf_key_start + index, WRITE, map, rd);
	return 0;
}

static int holepunch_write_pprf_key(struct eraser_dev *rd)
{
	struct page *p;
	char *map;
	unsigned sector_i;

	p = eraser_allocate_page(rd);
	map = kmap(p);

	for (sector_i = 0; sector_i < DIV_ROUND_UP(rd->hp_h->master_key_count, 
			HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR); ++sector_i) {
		holepunch_write_pprf_key_sector(rd, sector_i, map, false);
	}
	kunmap(p);
	eraser_free_page(p, rd);

	return 0;
}

/* If we are at the key limit, refresh pprf key
 * Call with PPRF write lock but no cache locks */
// static inline int holepunch_check_refresh_pprf_key(struct eraser_dev *rd,
// 		u32 punctures_requested, struct semaphore *cache_lock)
// {
// 	if (rd->pprf_fkt[0].master_key_count + 2*rd->hp_h->pprf_depth*punctures_requested 
// 			> rd->hp_h->master_key_limit) {
// 		++rd->stats_refresh;
// 		holepunch_refresh_pprf_key(rd, cache_lock);
// 		return 1;
// 	}
// 	return 0;
// }

// TODO Journal here
/* Lock PPRF read from outside 
 * This function will grab each cache lock at some point
 * If the calling function is already holding on to a cache lock,
 * pass it in so that we skip grabbing it here */
static int holepunch_refresh_pprf_key(struct eraser_dev *rd, 
		struct semaphore *cache_lock)
{
	int r;
	struct page *p;
	char *map;
	unsigned bucket;
	u64 index;
	u32 bot_sect_start, bot_sect_end;
	struct eraser_map_cache *c;

#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG(" == REFRESH COMMENCING == \n");
#endif

	bot_sect_start = 0;
	bot_sect_end = rd->hp_h->pprf_fkt_bottom_width;

	holepunch_alloc_master_key(rd, HOLEPUNCH_INITIAL_PPRF_SIZE, HOLEPUNCH_PPRF_REFRESH);
	holepunch_init_master_key(rd, HOLEPUNCH_PPRF_REFRESH);

	p = eraser_allocate_page(rd);
	map = kmap(p);

	// A lot of this is get_fkt_sector_cache_entry without the locking
	for (index = 0; index < rd->hp_h->pprf_fkt_start - rd->hp_h->key_table_start; ++index) {
		bucket = holepunch_hash_fkt_sectorno(rd, index);
		if (likely(&rd->cache_lock[bucket] != cache_lock))
			HP_DOWN(&rd->cache_lock[bucket], "Bucket refresh");
		c = eraser_search_map_cache(rd, index, bucket);
		if (!c) {
			c = eraser_cache_map(rd, index, bucket);
		}
		c->map->tag = index;
		eraser_write_map_cache(rd, c, HOLEPUNCH_PPRF_REFRESH);
		if (likely(&rd->cache_lock[bucket] != cache_lock))
			HP_UP(&rd->cache_lock[bucket], "Bucket refresh");
	}

	r = holepunch_refresh_pprf_fkt(rd, bot_sect_start, bot_sect_end);
	rd->hp_h->tag_counter = index;
	rd->hp_h->master_key_count = 1;

	// path of no return
	vfree(rd->pprf_master_key);
	rd->pprf_master_key = rd->new_pprf_master_key;
	rd->new_pprf_master_key = NULL;
	rd->pprf_master_key_capacity = rd->new_pprf_master_key_capacity;


	r = holepunch_write_pprf_key_sector(rd, 0, map, false);

	// Also refreshes the TPM here
	holepunch_write_pprf_fkt_top_sector(rd, 0, map, true);
	for (index = bot_sect_start; index < bot_sect_end; ++index) {
		holepunch_write_pprf_fkt_bottom_sector(rd, index, map, false);
	}
	kunmap(p);
	eraser_free_page(p, rd);

#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG(" == REFRESH COMPLETED == \n");
#endif
	return 0;
}


/* Drops all cache entries, writes them back to disk if dirty. .
 * PPRF write lock from outside */
static void eraser_force_evict_map_cache(struct eraser_dev *rd)
{
	struct eraser_map_cache *c;
	struct eraser_map_cache *n;
	int i;

	for (i = 0; i < ERASER_MAP_CACHE_BUCKETS; ++i) {
		down(&rd->cache_lock[i]);
		list_for_each_entry_safe(c, n, &rd->map_cache_list[i], list) {
			if (c->status & ERASER_CACHE_DIRTY)
				holepunch_persist_unlink(rd, c, &rd->cache_lock[i]);
			eraser_drop_map_cache(rd, c);
		}
		up(&rd->cache_lock[i]);
	}
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
#ifdef HOLEPUNCH_DEBUG
		KWORKERMSG("The reaper has awoken\n");
#endif
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
// 					KWORKERMSG("Reaper persisting sector %u\n", c->slot_no);
// #endif
					holepunch_persist_unlink(rd, c, &rd->cache_lock[i]); 
				}
				if (will_evict && (rd->map_cache_count > ERASER_CACHE_MEMORY_PRESSURE))
					eraser_drop_map_cache(rd, c);
			}
			up(&rd->cache_lock[i]);
		}

#ifdef HOLEPUNCH_DEBUG
		down_read(&rd->map_cache_count_sem);
		KWORKERMSG("The reaper shall return for another bounty... (Cached: %llu)\n", 
			rd->map_cache_count);
		up_read(&rd->map_cache_count_sem);
#endif
		msleep_interruptible(ERASER_CACHE_EVICTION_PERIOD * 1000);

		/*
		 * We do simple & stupid sleep wait instead of signaling. Proper
		 * eviction strategies should be studied for optimal performance.
		 */
		if (kthread_should_stop()) {
#ifdef HOLEPUNCH_DEBUG
			KWORKERMSG("The reaper bids farewell\n");
#endif
			return 0;
		}

	}

	return 0; /* Never. */
}


/* FKT functions (r/w/caching/retrieval) */

/* Search the cache for given keys. Lock cache from outside. */
static struct eraser_map_cache *eraser_search_map_cache(struct eraser_dev *rd, 
		unsigned sectorno, unsigned bucket)
{
	struct eraser_map_cache *c;

	list_for_each_entry(c, &rd->map_cache_list[bucket], list) {
		if (c->slot_no == sectorno) {
			c->last_access = jiffies;
			return c;
		}
	}

	return NULL; /* Not found. */
}

/* Read from disk the given keys, and cache. Lock cache from outside. 
 * PPRF is locked from outside */
static struct eraser_map_cache *eraser_cache_map(struct eraser_dev *rd, unsigned sectorno,
		unsigned bucket) 
{
	struct eraser_map_cache *c;

	/* Read map entries from disk. */
	c = eraser_allocate_map_cache(rd);
	c->map = __holepunch_read_key_table_sector(rd, sectorno);

	/* Set up the rest of the cache entry. */
	c->slot_no = sectorno;
	c->status = 0;
	c->first_access = jiffies;
	c->last_access = jiffies;

	/* Add to cache. */
	INIT_LIST_HEAD(&c->list);
	list_add(&c->list, &rd->map_cache_list[bucket]);
	down_write(&rd->map_cache_count_sem);
	rd->map_cache_count += 1;
	// KWORKERMSG("cache: %llu\n",rd->map_cache_count);
	up_write(&rd->map_cache_count_sem);


	return c;
}

/* Drop a cache entry. Lock from outside. */
static inline void eraser_drop_map_cache(struct eraser_dev *rd, struct eraser_map_cache *c)
{
	list_del(&c->list);
	eraser_free_sector((char *)c->map, rd);
	eraser_free_map_cache(c, rd);
	down_write(&rd->map_cache_count_sem);
	rd->map_cache_count -= 1;
	up_write(&rd->map_cache_count_sem);
}

/* Write a cache entry back to disk. Resets dirty bit.
 * Lock (PPRF, cache) from outside.  */
static void eraser_write_map_cache(struct eraser_dev *rd, struct eraser_map_cache *c, 
		unsigned mode)
{
	__holepunch_write_key_table_sector(rd, c->map, c->slot_no, mode);
	c->status = 0;
}

/* goes to the cache */
static void holepunch_get_key_for_inode(u64 inode_no, u8 *key, 
		struct eraser_dev *rd)
{
	struct holepunch_filekey_sector *sector;
	struct semaphore *cache_lock;
	int index;

	sector = holepunch_get_fkt_sector_cache_entry_for_inode(rd, inode_no, &cache_lock)->map;
	index = holepunch_get_sector_index_for_inode(rd, inode_no);

	memcpy(key, sector->entries[index].key, ERASER_KEY_LEN);

	HP_UP(cache_lock, "inode %llu get key", inode_no);
}

static inline unsigned holepunch_hash_fkt_sectorno(struct eraser_dev *rd,
		unsigned sectorno)
{
	return sectorno % ERASER_MAP_CACHE_BUCKETS;
}

static inline unsigned holepunch_get_fkt_sectorno_for_inode(struct eraser_dev *rd, 
	u64 ino) 
{
	return ino / HOLEPUNCH_FILEKEYS_PER_SECTOR;
}

/* Passes a locked cache_lock to caller
 * 1. Searches the cache for the fkt_sector
 * 2. If absent, loads and caches it 
 * 
 * For functions that also require the PPRF lock at some point,
 * it should be held on entry and not reacquired before cache lock is released */
static struct eraser_map_cache *holepunch_get_fkt_sector_cache_entry(struct eraser_dev *rd, 
		unsigned sectorno, struct semaphore **cache_lock) 
{
	struct eraser_map_cache *c;
	unsigned bucket;

	bucket = holepunch_hash_fkt_sectorno(rd, sectorno);

	HP_DOWN(&rd->cache_lock[bucket], "Bucket %u get entry", bucket);
	c = eraser_search_map_cache(rd, sectorno, bucket);
	if (!c) {
		c = eraser_cache_map(rd, sectorno, bucket);
	}

	*cache_lock = &rd->cache_lock[bucket];
	return c;
}

/* Needs PPRF (read++) lock held - see above */
static struct eraser_map_cache *holepunch_get_fkt_sector_cache_entry_for_inode
	(struct eraser_dev *rd, u64 ino, struct semaphore **cache_lock)
{
	unsigned sectorno;

	sectorno = holepunch_get_fkt_sectorno_for_inode(rd, ino);
	return holepunch_get_fkt_sector_cache_entry(rd, sectorno, cache_lock);
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
	struct bio *clone;
	struct bio *encrypted_bio;
	struct bio_vec vec;
	struct page *p;
	u8 key[ERASER_KEY_LEN];

	if (w->is_file) {
		holepunch_get_key_for_inode(
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			key, w->rd);
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
		holepunch_get_key_for_inode(
			bio_iter_iovec(w->bio, w->bio->bi_iter).bv_page->mapping->host->i_ino,
			key, w->rd);
	} else {
		memcpy(key, w->rd->sec_key, ERASER_KEY_LEN);
	}

	/* Read is complete at this point. Simply iterate over pages and
	 * decrypt. */
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

	// DMINFO("I/O from PID %i\n", task_pid_nr(current));

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

/* Lock cache from outside, but also pass it in:
 * this is in case we need to refresh
 * This will grab the PPRF write lock */
static int holepunch_persist_unlink(struct eraser_dev *rd,
		struct eraser_map_cache *c, struct semaphore *cache_lock) 
{
	u32 punctured_keynode_index, new_keynode_start_index, new_keynode_end_index;
	u32 punctured_keynode_sector, new_keynode_start_sector, new_keynode_end_sector;
	u64 old_tag;
	struct holepunch_filekey_sector *fktsector;
	struct page *p;
	char *map;

	HP_DOWN_WRITE(&rd->pprf_sem, "PPRF: persist unlink");

	/* If we refresh the PPRF, then we don't need to puncture again afterwards */
	if (rd->hp_h->master_key_count + 2*rd->hp_h->pprf_depth 
			> rd->hp_h->master_key_limit) {
		++rd->stats_refresh;
		HP_DOWNGRADE_WRITE(&rd->pprf_sem,"PPRF: persist > refresh");
		holepunch_refresh_pprf_key(rd, cache_lock);
		HP_UP_READ(&rd->pprf_sem, "PPRF: persist > refresh");
		return 0;
	}

	/* proceed with puncturing */
	fktsector = c->map;
	old_tag = fktsector->tag;

	fktsector->tag = rd->hp_h->tag_counter++;
// #ifdef HOLEPUNCH_DEBUG
// 	KWORKERMSG("Tag: %llu -> %llu\n", old_tag, fktsector->tag);
// #endif
	holepunch_puncture_at_tag(rd, old_tag, &punctured_keynode_index,
		&new_keynode_start_index, &new_keynode_end_index);

	punctured_keynode_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, punctured_keynode_index);
	new_keynode_start_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, new_keynode_start_index);
	new_keynode_end_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, new_keynode_end_index-1);

#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Keylength: %u/%u, limit:%u\n", rd->pprf_fkt[0].master_key_count,
		rd->pprf_master_key_capacity, rd->hp_h->master_key_limit);
	KWORKERMSG("PPRF keynode indices touched: %u %u %u\n",
		punctured_keynode_index, new_keynode_start_index, new_keynode_end_index);
	KWORKERMSG("PPRF keynode sectors touched: %u %u %u\n",
		punctured_keynode_sector, new_keynode_start_sector, new_keynode_end_sector);
	// holepunch_print_master_key(rd);
#endif
	// Persists new crypto information to disk
	p = eraser_allocate_page(rd);
	map = kmap(p);

	holepunch_write_pprf_key_sector(rd, punctured_keynode_sector, map, true);
	if (new_keynode_start_sector > punctured_keynode_sector) {
		holepunch_write_pprf_key_sector(rd, new_keynode_start_sector, map, false);
	}
	if (new_keynode_end_sector > new_keynode_start_sector)	{
		holepunch_write_pprf_key_sector(rd, new_keynode_end_sector, map, false);
	}
	kunmap(p);
	eraser_free_page(p, rd);
	HP_UP_WRITE(&rd->pprf_sem, "PPRF: persist unlink");

	eraser_write_map_cache(rd, c, HOLEPUNCH_PPRF_NORMAL);
#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Persist successful\n");
#endif
	return 0;
}


/* Bottom half for unlink operations. */
static void holepunch_do_unlink(struct work_struct *work)
{
	u64 index;
	struct eraser_map_cache *c;
	struct semaphore *cache_lock;

	struct eraser_unlink_work *w = container_of(work, struct eraser_unlink_work, work);
#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Unlinking\n");
#endif
	c = holepunch_get_fkt_sector_cache_entry_for_inode(w->rd, w->inode_no, &cache_lock);
	index = holepunch_get_sector_index_for_inode(w->rd, w->inode_no);

	/* rerolling the slot */
	kernel_random(c->map->entries[index].key, ERASER_KEY_LEN);
	c->status = ERASER_CACHE_DIRTY;

#ifndef HOLEPUNCH_BATCHING
	holepunch_persist_unlink(w->rd, c, cache_lock);
#endif
	HP_UP(cache_lock, "Cache: unlink");


	eraser_free_unlink_work(w);

// #ifdef HOLEPUNCH_DEBUG
// 	KWORKERMSG("Unlink completed\n");
// #endif
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
	// #ifdef HOLEPUNCH_DEBUG
	// 	DMINFO("request remapped from sector %u to sector %u\n", bio->bi_iter.bi_sector,
	// 							bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE));
	// #endif
	bio->bi_iter.bi_sector = bio->bi_iter.bi_sector + (rd->hp_h->data_start * ERASER_SECTOR_SCALE);

	if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
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
	char dummy;
	int helper_pid, i;

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
	holepunch_read_header(rd);
#ifdef HOLEPUNCH_DEBUG
	DMINFO("\nKernel-land info:\n");
	DMINFO("Key table start: %llu\n", rd->hp_h->key_table_start);
	DMINFO("Key table sectors: %llu\n", rd->hp_h->pprf_fkt_start - rd->hp_h->key_table_start);

	DMINFO("PPRF fkt start: %llu\n", rd->hp_h->pprf_fkt_start);
	DMINFO("PPRF fkt sectors: %llu\n", rd->hp_h->pprf_key_start - rd->hp_h->pprf_fkt_start);

	DMINFO("PPRF key start: %llu\n", rd->hp_h->pprf_key_start);
	DMINFO("PPRF key sectors: %llu\n", rd->hp_h->data_start - rd->hp_h->pprf_key_start);

	DMINFO("Data start: %llu\n", rd->hp_h->data_start);
	DMINFO("Data sectors: %llu\n", rd->hp_h->data_end - rd->hp_h->data_start);
	DMINFO("IV gen key %32ph\n", rd->hp_h->iv_key);
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

	if (unlikely(!rd->hp_h->initialized)) {
		// TODO put this in the userspace program
#ifdef HOLEPUNCH_DEBUG
		KWORKERMSG("Fresh holepunch: generating root pprf key\n");
#endif
		holepunch_alloc_pprf_fkt(rd);
		if (!rd->pprf_fkt) {
			ti->error = "Could not allocate pprf fkt.";
			goto read_pprf_fkt_fail;
		}
		holepunch_init_pprf_fkt(rd);

		holepunch_alloc_master_key(rd, HOLEPUNCH_INITIAL_PPRF_SIZE, HOLEPUNCH_PPRF_NORMAL);
		if (!rd->pprf_master_key) {
			ti->error = "Could not allocate pprf key.";
			goto read_pprf_key_fail;
		}
		holepunch_init_master_key(rd, HOLEPUNCH_PPRF_NORMAL);
		rd->hp_h->tag_counter = rd->hp_h->pprf_fkt_start - rd->hp_h->key_table_start;
		holepunch_write_pprf_fkt(rd);
		holepunch_write_pprf_key(rd);
		kernel_random(rd->hp_h->iv_key, ERASER_KEY_LEN);
		rd->hp_h->initialized = true;
		holepunch_write_header(rd);
#ifdef HOLEPUNCH_DEBUG
		KWORKERMSG("Holepunch crypto initialized!\n");
#endif
	} else {
#ifdef HOLEPUNCH_DEBUG
		DMINFO("Retrieving pprf key\n");
#endif
		holepunch_read_pprf_fkt(rd);
		if (!rd->pprf_fkt) {
			ti->error = "Could not read pprf fkt.";
			goto read_pprf_fkt_fail;
		}
		rd->pprf_master_key = holepunch_read_pprf_key(rd);
		if (!rd->pprf_master_key) {
			ti->error = "Could not read pprf key.";
			goto read_pprf_key_fail;
		}
	}
#ifdef HOLEPUNCH_DEBUG
	holepunch_print_master_key(rd);
#endif

	rd->evict_map_cache_thread = kthread_run(&holepunch_evict_map_cache, rd, "holepunch_evict");
	if (IS_ERR(rd->evict_map_cache_thread)) {
		ti->error = "Could not create cache evict thread.";
		goto create_evict_thread_fail;
	}

	/* Initialize locks */
	// rd->filekey_sem_array = vmalloc(rd->hp_h->key_table_len * 
	// 	sizeof(struct rw_semaphore));
	// if (!rd->filekey_sem_array) {
	// 	goto read_slot_map_fail;
	// }
	// for (i = 0; i< rd->hp_h->key_table_len; ++i) {
	// 	init_rwsem(rd->filekey_sem_array + i);
	// }
	init_rwsem(&rd->pprf_sem);
	// init_rwsem(&rd->job_sem);

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

	DMINFO("Success.");
	return 0;

	/* Lots to clean up after an error. */
create_evict_thread_fail:
	vfree(rd->pprf_master_key);
read_pprf_key_fail:
	vfree(rd->pprf_fkt);
read_pprf_fkt_fail:
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
	mempool_destroy(rd->page_pool);
create_page_pool_fail:
	bioset_free(rd->bioset);
create_bioset_fail:
	kfree(rd->prg_input);
init_prg_input_fail:
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

	eraser_force_evict_map_cache(rd);

	/* Keys no longer needed, wipe them. */
	// holepunch_write_pprf_key(rd);
	eraser_kill_helper(rd);
	memset(rd->new_master_key, 0, ERASER_KEY_LEN);
	memset(rd->master_key, 0, ERASER_KEY_LEN);
	memset(rd->sec_key, 0, ERASER_KEY_LEN);
	memset(rd->iv_key, 0, ERASER_KEY_LEN);

	/* Write header. */
	holepunch_write_header(rd);
	eraser_free_sector(rd->hp_h, rd);
	// eraser_write_header(rd->rh, rd);
	// eraser_free_sector(rd->rh, rd);

	vfree(rd->pprf_master_key);
	vfree(rd->pprf_fkt);
	// vfree(rd->key_table);

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
	/* .status = eraser_status, */
	/* .ioctl  = eraser_ioctl, */
	.io_hints = eraser_io_hints,
};

static void config_messages(void)
{
#ifdef HOLEPUNCH_BATCHING
	DMINFO("Batching enabled\n");
#else
	DMINFO("Batching disabled\n");
#endif
#ifdef HOLEPUNCH_DEBUG
	DMINFO("HOLEPUNCH compiled in debug mode\n");
#endif
	DMINFO("\nHOLEPUNCH_PPRF_KEYNODES_PER_SECTOR: %lu\n", HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR);
	DMINFO("HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR: %lu\n", HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR);
	DMINFO("HOLEPUNCH_FILEKEYS_PER_SECTOR: %lu\n", HOLEPUNCH_FILEKEYS_PER_SECTOR);
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
