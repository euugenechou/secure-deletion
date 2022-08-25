
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
	u8 key[PRG_INPUT_LEN];

	/* Read map entries from disk. */
	c = eraser_allocate_map_cache(rd);
	c->map = eraser_rw_sector(rd->hp_h->key_table_start + sectorno, READ, NULL, rd);

	HP_DOWN_READ(&rd->pprf_sem, "PPRF: read sector");
	holepunch_evaluate_at_tag(rd, c->map->tag, key, rd->pprf_master_key);
	HP_UP_READ(&rd->pprf_sem, "PPRF: read sector");
	// #ifdef HOLEPUNCH_DEBUG
	// 		DMINFO("READ TABLE: PPRF output for sector %u, tag %llu: %32ph \n",
	// 			sectorno, (map+sectorno)->tag, pprf_out);
	// #endif
	holepunch_cbc_filekey_sector(rd, c->map, c->map, ERASER_DECRYPT, key, rd->hp_h->key_table_start + sectorno);


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

/* Write a cache entry back to disk. Resets dirty bit.
 * Lock (PPRF, cache) from outside.  */
static void eraser_write_map_cache(struct eraser_dev *rd, struct eraser_map_cache *c, 
		unsigned mode)
{
	struct page *p;
	u8 pprf_out[PRG_INPUT_LEN];
	struct holepunch_filekey_sector *data;
	struct pprf_keynode *pprf;
	u64 sectorno = rd->hp_h->key_table_start + c->sector;

	if (likely(mode == HOLEPUNCH_PPRF_NORMAL))
		pprf = rd->pprf_master_key;
	else if (mode == HOLEPUNCH_PPRF_REFRESH)
		pprf = rd->new_pprf_master_key;

	p = eraser_allocate_page(rd);
	data = kmap(p);
	memcpy(data, c->map, ERASER_SECTOR);
	HP_DOWN_READ(&rd->pprf_sem, "PPRF: write sector");
	holepunch_evaluate_at_tag(rd, c->map->tag, pprf_out, pprf);
	HP_UP_READ(&rd->pprf_sem, "PPRF: write sector");
	holepunch_cbc_filekey_sector(rd, data, data, ERASER_ENCRYPT, pprf_out, sectorno);
	// TODO Journal here (part of a larger whole)
	eraser_rw_sector(sectorno, WRITE, data, rd);

	kunmap(p);
	eraser_free_page(p, rd);
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

	bucket = sectorno % ERASER_MAP_CACHE_BUCKETS;

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
#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Tag: %llu -> %llu\n", old_tag, fktsector->tag);
#endif
	holepunch_puncture_at_tag(rd, old_tag, &punctured_keynode_index,
		&new_keynode_start_index, &new_keynode_end_index);

	punctured_keynode_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, punctured_keynode_index);
	new_keynode_start_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, new_keynode_start_index);
	new_keynode_end_sector =
		holepunch_get_pprf_keynode_sector_for_keynode_index(rd, new_keynode_end_index-1);

#ifdef HOLEPUNCH_DEBUG
	KWORKERMSG("Keylength: %u/%u, limit:%u\n", rd->hp_h->master_key_count,
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
