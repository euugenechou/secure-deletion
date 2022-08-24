#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/fs.h>

#include "pprf-tree.h"

#ifdef HOLEPUNCH_PPRF_TIME
#include <linux/timekeeping.h>
#endif

inline bool check_bit_is_set(u64 tag, u8 depth) 
{
	return tag & (1ull << (63-depth));
}

inline void set_bit_in_buf(u64 *tag, u8 depth, bool val) 
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
	master_key->flag = PPRF_KEYLEAF;
}


/* Tree traversal
 *
 * Returns ptr to key or NULL if punctured
 * Additionally will write the node index to "index" if not NULL
 * Will initialize depth to 0
 */
struct pprf_keynode *find_key(struct pprf_keynode *pprf_base, u8 pprf_depth,
		u64 tag, u32 *depth, int *index) 
{
	unsigned i;
	struct pprf_keynode *cur;

	i = 0;
	*depth = 0;
	do {
		cur = pprf_base + i;
		if (likely(index)) {
			*index = i;
		}
		if (cur->flag == PPRF_KEYLEAF) {
			return cur;
		}
		if (cur->flag == PPRF_INTERNAL) {
			if(check_bit_is_set(tag, *depth))
				i = cur->v.next.ir;
			else
				i = cur->v.next.il;
		}
		++*depth;
	} while (*depth < pprf_depth);

	cur = pprf_base + i;
	if (cur->flag == PPRF_KEYLEAF) {
		return cur;
	}
	return NULL;
}
/*
New, but probably best to try things out a bit more in stages....
struct pprf_keynode *find_key(struct pprf_keynode *pprf_base, u8 pprf_depth,
		u64 tag, u32 *depth, int *index)
{
	struct pprf_keynode *cur = pprf_base;
	for (*depth = 0; *depth <= pprf_depth; ++*depth) {
		switch (cur->flag) {
			case PPRF_KEYLEAF:
				if (index)
					*index = cur - pprf_base;
				return cur;
			case PPRF_INTERNAL:
				/*
				 * Not sure why this was done, but I'm just replicating the old
				 * behavior exactly (except for faster puncture evals)
				 *//*
				if (*depth == pprf_depth)
					/* Theoretically, I guess this should never occur *//*
					return NULL;
				if (check_bit_is_set(tag, *depth))
					cur = pprf_base + cur->v.next.ir;
				else
					cur = pprf_base + cur->v.next.il;
				break;
			case PPRF_PUNCTURE:
				return NULL;
			default:
				/* This should never happen! *//*
				return NULL;
		}
	}
	return NULL;
}*/

/* PPRF puncture operation
 * 
 * Returns -1 if the puncture was not possible (eg if a puncture
 * at that tag had already been executed)
 * Otherwise returns the index of the PPRF keynode that was changed
 * as a result of the puncture (used for writeback purposes).
 */
int puncture(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data,
	u32 *master_key_count, u64 tag) {
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	int root_index;
	struct pprf_keynode *root;

	root = find_key(pprf_base, pprf_depth, tag, &depth, &root_index);
	// it will be NULL if its already been punctured, in which case we just return
	if (!root) {
		return -1;
	}

	// 2. find all neighbors in path
	memcpy(keycpy, root->v.key, PRG_INPUT_LEN);
	memset(root->v.key, 0, PRG_INPUT_LEN);
	root->flag = PPRF_INTERNAL;
	while (depth < pprf_depth) {
		p(data, keycpy, tmp);
		set = check_bit_is_set(tag, depth);
		if (set) {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			memcpy((pprf_base + *master_key_count)->v.key, tmp, PRG_INPUT_LEN);
			root->v.next.il = *master_key_count;
			root->v.next.ir = *master_key_count+1;
		} else {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
			memcpy((pprf_base + *master_key_count)->v.key, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			root->v.next.ir = *master_key_count;
			root->v.next.il = *master_key_count+1;
		}
	#ifdef HOLEPUNCH_DEBUG
		(pprf_base+*master_key_count)->lbl.label = tag;
		set_bit_in_buf(&(pprf_base+*master_key_count)->lbl.label, depth, !set);
		(pprf_base + *master_key_count)->lbl.depth = depth+1;

		(pprf_base+*master_key_count+1)->lbl.label = tag;
		set_bit_in_buf(&(pprf_base + *master_key_count+1)->lbl.label, depth, set);
		(pprf_base + *master_key_count+1)->lbl.depth = depth+1;
	#endif
		// (pprf_base + *master_key_count)->il = 0;
		// (pprf_base + *master_key_count)->ir = 0;
		(pprf_base + *master_key_count)->flag = PPRF_KEYLEAF;
		(pprf_base + *master_key_count+1)->flag = PPRF_INTERNAL;
		*master_key_count += 2;
		++depth;
		root = (pprf_base + *master_key_count-1);
	}
	// At the end of the loop, the root node is always a punctured node. So set links accordingly
	// root->il = -1;
	// root->ir = -1;
	root->flag = PPRF_PUNCTURE;

	return root_index;
}

int puncture_at_tag(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data,
		u32 *master_key_count, u64 tag)
{
	tag <<= (64-pprf_depth);
	return puncture(pprf_base, pprf_depth, p, data, master_key_count, tag);
}


/* PPRF evaluation
 * 	Returns -1 if the tag has been punctured
 * 	Otherwise returns 0 and out should be filled with the 
 * 	evaluation of PPRF(tag)
 */
int evaluate(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data, u64 tag, u8 *out)
{
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	struct pprf_keynode *root;

#ifdef HOLEPUNCH_DEBUG
	memset(out, 0xcc, PRG_INPUT_LEN);
#endif
	root = find_key(pprf_base, pprf_depth, tag, &depth, NULL);
	if (!root) 
		return -1;

	memcpy(keycpy, root->v.key, PRG_INPUT_LEN);

	for (; depth<pprf_depth; ++depth) {
		p(data, keycpy, tmp);
		set = check_bit_is_set(tag, depth);
		if (set) {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
		}
	}
	memcpy(out, keycpy, PRG_INPUT_LEN);
	return 0;
}

int evaluate_at_tag(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data, u64 tag, u8* out)
{
	tag <<= (64-pprf_depth);
	return evaluate(pprf_base, pprf_depth, p, data, tag, out);
}


#ifdef HOLEPUNCH_DEBUG
// printing functions
void label_to_string(struct node_label *lbl, char* node_label_str, u16 len) {
	u64 bit;
    int i;
	// u64 value = 0;
	memset(node_label_str, '\0', len);
	
	if (lbl->depth == 0) {
		node_label_str[0] = '\"';
		node_label_str[1] = '\"';
	} else {
		for (i=0; i<lbl->depth; ++i) {
			bit = check_bit_is_set(lbl->label, i);
			node_label_str[i] = bit ? '1' : '0';
		}
	}
}


void print_master_key(struct pprf_keynode *pprf_base, u32 *master_key_count) {
	u32 i;
	struct pprf_keynode *node;
	char node_label_str[8*NODE_LABEL_LEN+1];
	
	printk(KERN_INFO ": Master key dump START, len=%u:\n", *master_key_count);
	for (i=0; i<*master_key_count; ++i) {
		node = (pprf_base + i);
		label_to_string(&node->lbl, node_label_str, 8*NODE_LABEL_LEN+1);
		if (node->flag == PPRF_INTERNAL) {
			printk(KERN_INFO "n:%u, il:%u, ir:%u, label:%s\n",
				i, node->v.next.il, node->v.next.ir, node_label_str);
		} else if (node->flag == PPRF_KEYLEAF) {
			printk(KERN_INFO "n:%u, key: %32ph, label:%s\n",
				i, node->v.key, node_label_str);
		} else {
			printk(KERN_INFO "n:%u, <punctured>, label:%s\n", i, node_label_str);
		}
		// printk(KERN_INFO "n:%u, ", i);
		// printk(KERN_CONT "il:%u, ", node->il);
		// printk(KERN_CONT "ir:%u, ", node->ir);
		// printk(KERN_CONT "key:%32ph, ", node->key);
		// printk(KERN_CONT "label:%s\n", node_label_str);
	}
	printk(KERN_INFO ": END Master key dump\n");
}
#endif



#ifdef HOLEPUNCH_PPRF_TEST
/* PPRF unit tests */

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
