#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/fs.h>

#include "pprf-tree.h"

#ifdef HOLEPUNCH_PPRF_TIME
#include <linux/timekeeping.h>
#endif

static inline bool check_bit_is_set(u64 tag, u8 depth)
{
	return tag & (1ull << (63-depth));
}

static inline void set_bit_in_buf(u64 *tag, u8 depth, bool val)
{
	if (val)
		*tag |= (1ull << (63-depth));
	else
		*tag &= (-1ull) - (1ull << (63-depth));
}

// some of these need error returns

int alloc_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count, unsigned len)
{
	*max_master_key_count = len / (sizeof(struct pprf_keynode));
	if (*master_key) {
		vfree(*master_key);
	}
	*master_key = vmalloc(len);

	return (*master_key != NULL);
}

/* we may need to zero out more than just the master key because of things
 * like page-granularity writes
 */
void init_master_key(struct pprf_keynode *master_key, u32 *master_key_count, unsigned len)
{
	memset(master_key, 0, len);
    kernel_random(master_key->v.key, PRG_INPUT_LEN);
	if (master_key_count)
		*master_key_count = 1;
	master_key->type = PPRF_KEYLEAF;
}


/*
 * Basic tree traversal; returns the first keyleaf matching `tag`, or NULL if
 * punctured at `tag`. Sets `depth` to the depth of the relevant keyleaf.
 */
static struct pprf_keynode *find_key(struct pprf_keynode *pprf, u8 pprf_depth,
		u64 tag, u32 *depth)
{
	struct pprf_keynode *cur = pprf;
	for (*depth = 0; *depth < pprf_depth; ++*depth) {
		if (cur->type == PPRF_KEYLEAF) {
			break;
		} else if (cur->type == PPRF_INTERNAL) {
			if (check_bit_is_set(tag, *depth))
				cur = pprf + cur->v.next.ir;
			else
				cur = pprf + cur->v.next.il;
		} else {
			cur = NULL;
			break;
		}
	}
	return cur;
}

/* PPRF evaluation; returns 0 for success, -1 if `tag` was punctured. */
static int evaluate(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
	u64 tag, u8 *key)
{
	u32 depth;
	u8 in[PRG_INPUT_LEN];
	u8 out[PRG_INPUT_LEN*2];
	struct pprf_keynode *root = find_key(pprf, pprf_depth, tag, &depth);
	if (!root)
		return -1;

	memcpy(in, root->v.key, PRG_INPUT_LEN);
	for (; depth < pprf_depth; ++depth) {
		p(data, in, out);
		if (check_bit_is_set(tag, depth)) {
			memcpy(in, out + PRG_INPUT_LEN, PRG_INPUT_LEN);
		} else {
			memcpy(in, out, PRG_INPUT_LEN);
		}
	}
	memcpy(key, in, PRG_INPUT_LEN);
	return 0;
}

int evaluate_at_tag(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
	u64 tag, u8* key)
{
	tag <<= 64 - pprf_depth;
	return evaluate(pprf, pprf_depth, p, data, tag, key);
}

/*
 * PPRF puncturing; returns -1 if the puncture was not possible (`tag` was
 * already punctured), otherwise the index of the PPRF keynode that was changed
 * as a result of the puncture (used for writeback purposes).
 */
static int puncture(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
		u32 *pprf_size, u64 tag) 
{
	u32 depth;
	u8 in[PRG_INPUT_LEN];
	u8 out[PRG_INPUT_LEN*2];
	int index, set;
	struct pprf_keynode *root = find_key(pprf, pprf_depth, tag, &depth);
	if (!root)
		return -1;

	memcpy(in, root->v.key, PRG_INPUT_LEN);
	memset(root->v.key, 0, PRG_INPUT_LEN);
	root->type = PPRF_INTERNAL;
	index = root - pprf;
	for (; depth < pprf_depth; ++depth) {
		p(data, in, out);
		set = check_bit_is_set(tag, depth);
		if (set) {
			memcpy(in, out + PRG_INPUT_LEN, PRG_INPUT_LEN);
			memcpy((pprf + *pprf_size)->v.key, out, PRG_INPUT_LEN);
			root->v.next.il = *pprf_size;
			root->v.next.ir = *pprf_size + 1;
		} else {
			memcpy(in, out, PRG_INPUT_LEN);
			memcpy((pprf + *pprf_size)->v.key, out + PRG_INPUT_LEN, PRG_INPUT_LEN);
			root->v.next.ir = *pprf_size;
			root->v.next.il = *pprf_size + 1;
		}
#ifdef HOLEPUNCH_DEBUG
		(pprf + *pprf_size)->lbl.label = tag;
		set_bit_in_buf(&(pprf + *pprf_size)->lbl.label, depth, !set);
		(pprf + *pprf_size)->lbl.depth = depth + 1;

		(pprf + *pprf_size + 1)->lbl.label = tag;
		set_bit_in_buf(&(pprf + *pprf_size + 1)->lbl.label, depth, set);
		(pprf + *pprf_size + 1)->lbl.depth = depth + 1;
#endif
		(pprf + *pprf_size)->type = PPRF_KEYLEAF;
		(pprf + *pprf_size + 1)->type = PPRF_INTERNAL;
		root = pprf + *pprf_size + 1;
		*pprf_size += 2;
	}
	root->type = PPRF_PUNCTURE;

	return index;
}

int puncture_at_tag(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
		u32 *pprf_size, u64 tag)
{
	tag <<= 64 - pprf_depth;
	return puncture(pprf, pprf_depth, p, data, pprf_size, tag);
}

#ifdef HOLEPUNCH_DEBUG
void label_to_string(struct node_label *lbl, char *node_label)
{
    int i;
	if (lbl->depth == 0) {
		strcpy(node_label, "\"\"");
	} else {
		for (i = 0; i < lbl->depth; ++i) {
			node_label[i] = check_bit_is_set(lbl->label, i) ? '1' : '0';
		}
		node_label[i] = '\0';
	}
}

void dump_key(u8 *key, char *name)
{
	char buf[PRG_INPUT_LEN * 3 + 1];
	int i;
	for (i = 0; i < PRG_INPUT_LEN; ++i) {
		sprintf(buf + i * 3, "%02hhx ", key[i]);
	}
	buf[sizeof(buf) - 1] = '\0';
	if (name)
		printk(KERN_INFO "%s: %s\n", name, buf);
	else
		printk(KERN_INFO "%s\n", buf);
}

void print_pprf(struct pprf_keynode *pprf, u32 pprf_size)
{
	u32 i;
	char node_label[MAX_DEPTH + 1];
	unsigned len = 80; /* Dangerous */
	char title[len];

	printk(KERN_INFO "PPRF dump, len %u", pprf_size);
	for (i = 0; i < pprf_size; ++i) {
		label_to_string(&pprf[i].lbl, node_label);
		if (pprf[i].type == PPRF_INTERNAL) {
			printk(KERN_INFO "[I] index %u, il: %u ir: %u\n label %s\n", i,
				pprf[i].v.next.il, pprf[i].v.next.ir, node_label);
		} else if (pprf[i].type == PPRF_KEYLEAF) {
			memset(title, 0, len);
			sprintf(title, "[K] index %u ", i);
			dump_key(pprf[i].v.key, title);
			snprintf(title, len, "label %s", node_label);
			printk(KERN_INFO "%s", title);
		} else {
			printk(KERN_INFO "[P] index %u\n label %s\n", i, node_label);
		}
	}
}
#endif

#ifdef PPRF_TEST
void test_puncture_0(struct pprf_keynode **base, u32 *max_count, u32 *count,
		struct crypto_blkcipher *tfm, u8 *iv) {
	int r;
	u8 pprf_depth;

	alloc_master_key(base, max_count, 4096);

	init_master_key(*base, count, 4096);
	print_master_key(*base, count);
	printk(KERN_INFO "Setting pprf depth = 2\n");
	pprf_depth = 2;

	printk(KERN_INFO "Puncturing 10...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 2);
	print_master_key(*base, count);


	printk(" ... resetting...\n");

	init_master_key(*base, count, 4096);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing 01...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 1);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing 10...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 2);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing 01 again...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 1);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing 11...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 3);
	print_master_key(*base, count);


}

void test_puncture_1(struct pprf_keynode **base, u32 *max_count, u32 *count,
		struct crypto_blkcipher *tfm, u8 *iv) {
	int r;
	u8 pprf_depth;

	alloc_master_key(base, max_count, 4096);

	init_master_key(*base, count, 4096);
	print_master_key(*base, count);
	printk(KERN_INFO "Setting pprf depth = 16\n");
	pprf_depth = 16;

	printk(KERN_INFO "Puncturing tag=0...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 0);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing tag=1...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 1);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing tag=2...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 2);
	print_master_key(*base, count);

	printk(KERN_INFO "Puncturing tag=65535...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 65535);
	print_master_key(*base, count);
}

void test_evaluate_0(struct pprf_keynode **base, u32 *max_count, u32 *count,
		struct crypto_blkcipher *tfm, u8 *iv) {
	int r;
	u8 pprf_depth;
	u8 out[PRG_INPUT_LEN];

	alloc_master_key(base, max_count, 4096);

	init_master_key(*base, count, 4096);
	print_master_key(*base, count);
	printk(KERN_INFO "Setting pprf depth = 16\n");
	pprf_depth = 16;


	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 0, out);
	printk(KERN_INFO "Evaluation at tag 0: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 1, out);
	printk(KERN_INFO "Evaluation at tag 1: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 255, out);
	printk(KERN_INFO "Evaluation at tag 255: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

	printk(KERN_INFO "Puncturing tag=1...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 1);
	print_master_key(*base, count);

	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 0, out);
	printk(KERN_INFO "Evaluation at tag 0: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 1, out);
	printk(KERN_INFO "Evaluation at tag 1: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 255, out);
	printk(KERN_INFO "Evaluation at tag 255: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

	printk(KERN_INFO "Puncturing tag=0...\n");
	r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, 0);
	print_master_key(*base, count);

	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 0, out);
	printk(KERN_INFO "Evaluation at tag 0: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 1, out);
	printk(KERN_INFO "Evaluation at tag 1: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(*base, iv, tfm, pprf_depth, 255, out);
	printk(KERN_INFO "Evaluation at tag 255: %s (%32ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

}

void test_evaluate_1(struct pprf_keynode **base, u32 *max_count, u32 *count,
		struct crypto_blkcipher *tfm, u8 *iv) {
	int r,i,rd;
	u8 pprf_depth;
	u8 out[PRG_INPUT_LEN];

	alloc_master_key(base, max_count, 8192);

	init_master_key(*base, count, 8192);
	print_master_key(*base, count);
	printk(KERN_INFO "Setting pprf depth = 32\n");
	pprf_depth = 32;

	for (rd=0; rd<16; ++rd) {
		printk(KERN_INFO "\n  puncture at tag=%u\n", rd);
		r = puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, rd);
		for (i=0; i<16; ++i) {
			r = evaluate_at_tag(*base, iv, tfm, pprf_depth, i, out);
			printk(KERN_INFO "Evaluation at tag %u: %s (%32ph)\n", i, r == 0?"SUCCESS" :"PUNCTURED", out);
		}
	}

}

void run_tests(void) {
	struct pprf_keynode *base;
	u32 max_count, count;

	base = NULL;

	printk(KERN_INFO "\n running test_puncture_0\n");
	test_puncture_0(&base, &max_count, &count, tfm, iv);
	printk(KERN_INFO "\n running test_puncture_1\n");
	test_puncture_1(&base, &max_count, &count, tfm, iv);

	printk(KERN_INFO "\n running test_evaluate_0\n");
	test_evaluate_0(&base, &max_count, &count, tfm, iv);
	printk(KERN_INFO "\n running test_evaluate_1\n");
	test_evaluate_1(&base, &max_count, &count, tfm, iv);

	printk(KERN_INFO "\n tests complete\n");

	vfree(base);
}
#endif


#ifdef HOLEPUNCH_PPRF_TIME
void evaluate_n_times(u64* tag_array, int reps, struct pprf_keynode **base, u32 *max_count,
		u32 *count,	struct crypto_blkcipher *tfm, u8 *iv, u8 pprf_depth) {
	int n;
	u64 nsstart, nsend;
	u8 out[PRG_INPUT_LEN];

	kernel_random((u8*) tag_array, sizeof(u64)*reps);
	printk(KERN_INFO "Begin evaluation: keylength = %u\n", *count);
	nsstart = ktime_get_ns();
	for(n=0; n<reps; ++n) {
		evaluate_at_tag(*base, iv, tfm, pprf_depth, tag_array[n], out);
	}
	nsend = ktime_get_ns();
	printk(KERN_INFO "Time per eval: %lld us\n", (nsend-nsstart)/1000/reps);
}

void puncture_n_times(u64* tag_array, int reps, struct pprf_keynode **base, u32 *max_count,
		u32 *count,	struct crypto_blkcipher *tfm, u8 *iv, u8 pprf_depth) {
	int n;
	u64 nsstart, nsend;

	kernel_random((u8*) tag_array, reps*sizeof(u64));
	printk(KERN_INFO "Puncturing %u times:\n", reps);
	nsstart = ktime_get_ns();
	for (n=0; n<reps; ++n) {
		puncture_at_tag(*base, iv,tfm, pprf_depth, count, max_count, tag_array[n]);
	}
	nsend = ktime_get_ns();
	printk(KERN_INFO "Time per puncture: %lld us\n", (nsend-nsstart)/1000/reps);
}

void preliminary_benchmark_cycle(void) {
	struct pprf_keynode *base;
	u32 max_count, count;
	u8 pprf_depth;
	u64 *tag_array;
	int maxreps = 100000;

	base = NULL;
	pprf_depth = 17;

	printk(KERN_INFO "Depth = %u, %u reps per eval cycle\n", pprf_depth, maxreps);

	tag_array = vmalloc(maxreps* sizeof(u64));
	alloc_master_key(&base, &max_count,
		2*pprf_depth*sizeof(struct pprf_keynode)*30000);
	init_master_key(base, &count, 4096);

	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 100, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 400, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 500, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 1000, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 3000, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 5000, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);
	puncture_n_times(tag_array, 15000, &base, &max_count, &count, tfm, iv, pprf_depth);
	evaluate_n_times(tag_array, maxreps, &base, &max_count, &count, tfm, iv, pprf_depth);

	vfree(tag_array);
}

void preliminary_benchmark(void) {
	preliminary_benchmark_cycle();
}
#endif
