#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/fs.h>
#include <linux/kernel.h>

#include "pprf-tree.h"

#ifdef TIME
#include <linux/timekeeping.h>
#endif



// u8 iv[PRG_INPUT_LEN];
struct scatterlist sg_in;
struct crypto_blkcipher *tfm;
// u8 pprf_depth;
// pprf_keynode* master_key;
// int master_key_count; // how many individual keys make up the master key
// int max_master_key_count;


void reset_pprf_keynode(pprf_keynode *node) {
// 	node->il = 0;
// 	node->ir = 0;
// 	memset(node->key, 0xcc, PRG_INPUT_LEN);
// #ifdef DEBUG
// 	memset(node->lbl.bstr, 0xcc, NODE_LABEL_LEN);
// 	node->lbl.depth = 0;
// #endif
	memset(node, 0, sizeof(pprf_keynode));
}


/* Returns crypto-safe random bytes from kernel pool. 
   Taken from eraser code */
inline void ggm_prf_get_random_bytes_kernel(u8 *data, u64 len)
{
	crypto_get_default_rng();
	crypto_rng_get_bytes(crypto_default_rng, data, len);
	crypto_put_default_rng();
}


int prg_from_aes_ctr(u8* key, u8* iv, struct crypto_blkcipher *tfm, u8* buf) {
	struct blkcipher_desc desc;
	struct scatterlist dst;
	// see comment in eraser code around ln 615 --  will this affect us?
	desc.tfm = tfm;
	desc.flags = 0;
	crypto_blkcipher_setkey(desc.tfm, key, PRG_INPUT_LEN);
	crypto_blkcipher_set_iv(desc.tfm, iv, PRG_INPUT_LEN);

	sg_init_one(&dst, buf, 2*PRG_INPUT_LEN);
	return crypto_blkcipher_encrypt(&desc, &dst, &sg_in, 2*PRG_INPUT_LEN);
}

bool check_bit_is_set(u8* buf, u8 index) {
	return buf[index/8] & (1 << (index%8));
}

void set_bit_in_buf(u8* buf, u8 index, bool val) {
	if (val)
		buf[index/8] |= (1 << (index%8));
	else
		buf[index/8] &= ((u8)-1) - (1 << (index%8));
}


// some of these need error returns

int alloc_master_key(pprf_keynode **master_key, u32 *max_master_key_count, unsigned len) {
	*max_master_key_count = len / (sizeof(pprf_keynode));
	if (*master_key) {
		vfree(*master_key);
	}
	*master_key = vmalloc(len);

	return (*master_key != NULL);
}


int expand_master_key(pprf_keynode **master_key, u32 *max_master_key_count, unsigned factor) {
	pprf_keynode *tmp;
#ifdef DEBUG
	printk("RESIZING: current capacity = %u\n", *max_master_key_count);
#endif	
	tmp = vmalloc((*max_master_key_count)*factor*sizeof(pprf_keynode));
	if (!tmp)
		return -ENOMEM;
	memcpy(tmp, *master_key, sizeof(pprf_keynode) * (*max_master_key_count));
	vfree(*master_key);
	*max_master_key_count *= factor;
	*master_key = tmp;
#ifdef DEBUG
	printk("RESIZING DONE: final capacity = %u\n", *max_master_key_count);
#endif	

	return 0;
}

/* we may need to zero out more than just the master key because of things
 * like page-granularity writes
 */
void init_master_key(pprf_keynode *master_key, u32 *master_key_count, unsigned len) {
	memset(master_key, 0, len);
    ggm_prf_get_random_bytes_kernel(master_key->key, PRG_INPUT_LEN);
	*master_key_count = 1;
}

void init_node_label_from_bitstring(node_label *lbl, const char* bitstring) {
	int i;
	memset(lbl->bstr, 0, NODE_LABEL_LEN);
	lbl->depth = strlen(bitstring);
	for (i=0; i<lbl->depth; ++i) {
		set_bit_in_buf(lbl->bstr, i, bitstring[i] == '1');
		// lbl->bstr[i/8] += (bitstring[i] == '1' ? 1 : 0) * (1 << (i%8));
	}
}

void init_node_label_from_long(struct node_label *lbl, u8 pprf_depth, u64 val) {
	u8 idx;

	lbl->depth = pprf_depth;
	for (idx=0; idx<pprf_depth; ++idx) {
		set_bit_in_buf(lbl->bstr, pprf_depth-1-idx, (1<<idx) & val);
	}
}

// void init_node_label_from_long(node_label *lbl, u64 u) {
// 	__be64 bigendian = cpu_to_be64(u);
// 	memcpy(lbl->bstr, (u8*) &bigendian, NODE_LABEL_LEN);
// 	lbl->depth = pprf_depth;
// }


/* tree traversal
 * returns ptr to key or NULL if punctured
 * will initialize depth to 0
 */ 
pprf_keynode *find_key(pprf_keynode *master_key, u8 pprf_depth, node_label *lbl, u32 *depth) {
	u32 i;
	pprf_keynode *cur;
	
	i = 0;
	*depth = 0;
	do {
		cur = master_key+i;
		if(check_bit_is_set(lbl->bstr, *depth)) 
			i = cur->ir;
		else
			i = cur->il;
	// if equals 0, leaf
	// if equals -1, punctured (currently does not occur before pprf_depth)
		if (i == 0) 
			return cur;
		// else if (i == (u32)-1)
		// 	return NULL;
		++*depth;
	} while (*depth < pprf_depth);

	cur = master_key+i;
	if (cur->il == 0)
		return cur;
	return NULL;
}

/* PPRF puncture operation
 * 
 * returns -1 if the puncture was not possible (eg if a puncture
 * at that tag had already been executed)
 */
int puncture(pprf_keynode *master_key, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u32 *master_key_count, u32 *max_master_key_count, node_label *lbl) {
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	pprf_keynode *root;
	
	root = find_key(master_key, pprf_depth, lbl, &depth);
	
	// it will be NULL if its already been punctured, in which case we just return
	if (!root)
		return -1;

	// now we traverse
	// 2. find all neighbors in path

	memcpy(keycpy, root->key, PRG_INPUT_LEN);
	memset(root->key, 0xcc, PRG_INPUT_LEN);
	while (depth < pprf_depth) {
		prg_from_aes_ctr(keycpy, iv, tfm, tmp);
		set = check_bit_is_set(lbl->bstr, depth);
		if (set) {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			memcpy((&master_key[*master_key_count])->key, tmp, PRG_INPUT_LEN);
			root->il = *master_key_count;
			root->ir = *master_key_count+1;
		} else {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
			memcpy((&master_key[*master_key_count])->key, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			root->ir = *master_key_count;
			root->il = *master_key_count+1;
		}
	#ifdef DEBUG
		memcpy(&master_key[*master_key_count].lbl, lbl, sizeof(node_label));
		set_bit_in_buf(master_key[*master_key_count].lbl.bstr, depth, !set);
		master_key[*master_key_count].lbl.depth = depth+1;

		memcpy(&master_key[*master_key_count+1].lbl, lbl, sizeof(node_label));
		set_bit_in_buf(master_key[*master_key_count+1].lbl.bstr, depth, set);
		master_key[*master_key_count+1].lbl.depth = depth+1;
	#endif
		master_key[*master_key_count].il = 0;
		master_key[*master_key_count].ir = 0;
		*master_key_count += 2;
		++depth;
		root = master_key + *master_key_count-1;
	}
	// At the end of the loop, the root node is always a punctured node. So set links accordingly
	root->il = -1;
	root->ir = -1;	
	
	return 0;
}

int puncture_at_tag(pprf_keynode *master_key, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u32 *master_key_count, u32 *max_master_key_count, u64 tag) {
	node_label lbl;
	init_node_label_from_long(&lbl, pprf_depth, tag);

	return puncture(master_key, iv, tfm, pprf_depth,
			master_key_count, max_master_key_count, &lbl);
}


/* PPRF evaluation
 * 	Returns -1 if the tag has been punctured
 * 	Otherwise returns 0 and out should be filled with the 
 * 	evaluation of PPRF(tag)
 */
int evaluate(pprf_keynode *master_key, u8* iv, struct crypto_blkcipher *tfm,
		u8 pprf_depth, node_label *lbl, u8 *out) {
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	pprf_keynode *root; 
	
#ifdef DEBUG
	memset(out, 0xcc, PRG_INPUT_LEN);
#endif

	root = find_key(master_key, pprf_depth, lbl, &depth);
	if (!root) 
		return -1;

	memcpy(keycpy, root->key, PRG_INPUT_LEN);

	for (; depth<pprf_depth; ++depth) {
		prg_from_aes_ctr(keycpy, iv, tfm, tmp);
		set = check_bit_is_set(lbl->bstr, depth);
		if (set) {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
		}
	}
	memcpy(out, keycpy, PRG_INPUT_LEN);
	return 0;
}


int evaluate_at_tag(pprf_keynode *master_key, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u64 tag, u8* out) {
	node_label lbl;
	init_node_label_from_long(&lbl, pprf_depth, tag);

	return evaluate(master_key, iv, tfm, pprf_depth, &lbl, out);
}



#ifdef DEBUG
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
			bit = check_bit_is_set(lbl->bstr, i);
			node_label_str[i] = bit ? '1' : '0';
			// value += bit << i;
		}
		// snprintf(node_label_str + lbl->depth + 1, len - lbl->depth, "(%llu)", value);
	}
}

// prints the key that evaluates this label (or none if punctured)
void print_pkeynode_debug(pprf_keynode *master_key, u8 pprf_depth, node_label *lbl) {
    // terrible terrible stringy stuff
	int depth;
    char node_label_str[8*NODE_LABEL_LEN+21];
	pprf_keynode *pkey;

	label_to_string(lbl, node_label_str, 8*NODE_LABEL_LEN+21);
	pkey = find_key(master_key, pprf_depth, lbl, &depth);

	printk(" Finding key for label %s ...\n", node_label_str);
	if (pkey) {
		label_to_string(&pkey->lbl, node_label_str, 8*NODE_LABEL_LEN+21);
		printk(KERN_INFO "PPRF KEY: %16ph, label: %s, depth: %d\n"
				, pkey->key, node_label_str, pkey->lbl.depth);
	} else {
		printk(KERN_INFO "Key not present\n");
	}    
}


void print_master_key(pprf_keynode *master_key, u32 *master_key_count) {
	u32 i;
	char node_label_str[8*NODE_LABEL_LEN+1];

	printk(KERN_INFO ": Master key dump START, len=%u:\n", *master_key_count);
	i=0;
	for (; i<*master_key_count; ++i) {
		label_to_string(&master_key[i].lbl, node_label_str, 8*NODE_LABEL_LEN+1);
		printk(KERN_INFO "n:%u, il:%u, ir:%u, key:%16ph, label:%s\n",
			i, master_key[i].il, master_key[i].ir, master_key[i].key, node_label_str);
		// printk(KERN_INFO "n:%u, ", i);
		// printk(KERN_CONT "il:%u, ", master_key[i].il);
		// printk(KERN_CONT "ir:%u, ", master_key[i].ir);
		// printk(KERN_CONT "key:%16ph, ", master_key[i].key);
		// printk(KERN_CONT "label:%s\n", node_label_str);
	}

	printk(KERN_INFO ": END Master key dump\n");

}


// // tests

// void test_print_pkey(void) {
// 	// will just print the node corresponding to 0
// 	node_label lbl;
// 	memset(lbl.bstr, 0, NODE_LABEL_LEN);
// 	lbl.depth = pprf_depth;
	
// 	print_pkeynode_debug(&lbl);
// }

// void test_cpu_to_be64(void) {
// 	node_label lbl;
// 	char node_label_str[8*NODE_LABEL_LEN+1];
// 	pprf_depth = 16;

// 	init_node_label_from_long(&lbl, 1);
// 	label_to_string(&lbl, node_label_str);
// 	printk(KERN_INFO "label is %s", node_label_str);
// }

// void test_puncture_0(void) {
// 	node_label punct_node;
// 	int r;

// 	init_master_key();
// 	print_master_key();
// 	printk(KERN_INFO "Setting pprf depth = 2\n");
// 	pprf_depth = 2;

// 	printk(KERN_INFO "Puncturing 10...\n");
// 	init_node_label_from_bitstring(&punct_node, "10");
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(" ... resetting...\n");

// 	init_master_key();
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing 01...\n");
// 	init_node_label_from_bitstring(&punct_node, "01");
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing 10...\n");
// 	init_node_label_from_bitstring(&punct_node, "10");
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing 01 again...\n");
// 	init_node_label_from_bitstring(&punct_node, "01");
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r != -1));	
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing 11...\n");
// 	init_node_label_from_bitstring(&punct_node, "11");
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// }

// void test_puncture_1(void) {
// 	node_label punct_node;
// 	int r;

// 	init_master_key();
// 	print_master_key();
// 	printk(KERN_INFO "Setting pprf depth = 16\n");
// 	pprf_depth = 16;

// 	printk(KERN_INFO "Puncturing tag=0...\n");
// 	init_node_label_from_long(&punct_node, 0);
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing tag=1...\n");
// 	init_node_label_from_long(&punct_node, 1);
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing tag=2...\n");
// 	init_node_label_from_long(&punct_node, 2);
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	printk(KERN_INFO "Puncturing tag=65535...\n");
// 	init_node_label_from_long(&punct_node, (1<<16)-1);
// 	r = puncture(&punct_node);
// 	BUG_ON(unlikely(r));
// 	print_master_key();
// }

// void test_evaluate_0(void) {
// 	init_master_key();
// 	print_master_key();
// 	printk(KERN_INFO "Setting pprf depth = 16\n");
// 	pprf_depth = 16;

// 	int r;
// 	u8 out[PRG_INPUT_LEN];

// 	r = evaluate_at_tag(0, out);
// 	printk(KERN_INFO "Evaluation at tag 0: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(1, out);
// 	printk(KERN_INFO "Evaluation at tag 1: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(255, out);
// 	printk(KERN_INFO "Evaluation at tag 255: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

// 	printk(KERN_INFO "Puncturing tag=1...\n");
// 	r = puncture_at_tag(1);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	r = evaluate_at_tag(0, out);
// 	printk(KERN_INFO "Evaluation at tag 0: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(1, out);
// 	printk(KERN_INFO "Evaluation at tag 1: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(255, out);
// 	printk(KERN_INFO "Evaluation at tag 255: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

// 	printk(KERN_INFO "Puncturing tag=0...\n");
// 	r = puncture_at_tag(0);
// 	BUG_ON(unlikely(r));
// 	print_master_key();

// 	r = evaluate_at_tag(0, out);
// 	printk(KERN_INFO "Evaluation at tag 0: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(1, out);
// 	printk(KERN_INFO "Evaluation at tag 1: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// 	r = evaluate_at_tag(255, out);
// 	printk(KERN_INFO "Evaluation at tag 255: %s (%16ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
// }

// void test_evaluate_1(void) {
// 	init_master_key();
// 	printk(KERN_INFO "Setting pprf depth = 64\n");
// 	pprf_depth = 64;

// 	int r,i,rd;
// 	u8 out[PRG_INPUT_LEN];
// 	for (rd=0; rd<16; ++rd) {
// 		printk(KERN_INFO "\n  puncture at tag=%u\n", rd);
// 		r = puncture_at_tag(rd);
// 		BUG_ON(unlikely(r));
// 		for (i=0; i<16; ++i) {
// 			r = evaluate_at_tag(i, out);
// 			BUG_ON(unlikely(r && i>rd));
// 			printk(KERN_INFO "Evaluation at tag %u: %s (%16ph)\n", i, r == 0?"SUCCESS" :"PUNCTURED", out);
// 		}
// 	}

// }


// void run_tests(void) {
// 	print_master_key();
// 	printk(KERN_INFO "\n running test_print_pkey\n");
// 	test_print_pkey();

// 	printk(KERN_INFO "\n running test_cpu_to_be64\n");
// 	test_cpu_to_be64();

// 	printk(KERN_INFO "\n running test_puncture_0\n");
// 	test_puncture_0();	
// 	printk(KERN_INFO "\n running test_puncture_1\n");
// 	test_puncture_1();

// 	printk(KERN_INFO "\n running test_evaluate_0\n");
// 	test_evaluate_0();
// 	printk(KERN_INFO "\n running test_evaluate_1\n");
// 	test_evaluate_1();

// 	printk(KERN_INFO "\n tests complete\n");

// }
// #endif


// // Some preliminary benchmarking
// #ifdef TIME
// void evaluate_n_times(u64* tag_array, int count) {
// 	int n;
// 	u64 nsstart, nsend;

// 	ggm_prf_get_random_bytes_kernel((u8*) tag_array, sizeof(u64)*count);
// 	printk(KERN_INFO "Begin evaluation: keylength = %u\n", master_key_count);
// 	nsstart = ktime_get_ns();
// 	for(n=0; n<count; ++n) {
// 		u8 out[PRG_INPUT_LEN];
// 		evaluate_at_tag(tag_array[n], out);
// 	}
// 	nsend = ktime_get_ns();
// 	printk(KERN_INFO /*"Time: %llu us\n"*/"Time per eval: %d us\n", /*(nsend-nsstart)/1000, */(nsend-nsstart)/1000/count);
// }

// void puncture_n_times(u64* tag_array, int count) {
// 	int n;
// 	u64 nsstart, nsend;

// 	ggm_prf_get_random_bytes_kernel((u8*) tag_array, count*sizeof(u64));
// 	printk(KERN_INFO "Puncturing %u times:\n", count);
// 	nsstart = ktime_get_ns();
// 	for (n=0; n<count; ++n) {
// 		puncture_at_tag(tag_array[n]);
// 	}
// 	nsend = ktime_get_ns();
// 	printk(KERN_INFO /*"Time: %llu us\n"*/"Time per puncture: %d us\n", /*(nsend-nsstart)/1000, */(nsend-nsstart)/1000/count);
// }

// void preliminary_benchmark_cycle(void) {
// 	init_master_key();
// 	pprf_depth = 64;

// 	int maxcount = 100000;
// 	int count;
	
// 	u64 *tag_array;
// 	tag_array = kmalloc_array(maxcount, sizeof(long), GFP_KERNEL);

// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 100);
// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 400);
// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 500);
// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 1000);
// 	evaluate_n_times(tag_array, maxcount);
// 	// Getting OOM
// 	puncture_n_times(tag_array, 3000);
// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 5000);
// 	evaluate_n_times(tag_array, maxcount);
// 	puncture_n_times(tag_array, 15000);
// 	evaluate_n_times(tag_array, maxcount);

// 	kfree(tag_array);
// }

// void preliminary_benchmark(void) {	
// 	preliminary_benchmark_cycle();
// }

#endif
