#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <crypto/rng.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>

#include <linux/timekeeping.h>

#define PRG_INPUT_LEN 16

u8 aes_input[2*PRG_INPUT_LEN] = "\000\001\002\003\004\005\006\007"
								"\010\011\012\013\014\015\016\017"
								"\020\021\022\023\024\025\026\027"
								"\030\031\032\033\034\035\036\037";

u8 iv[PRG_INPUT_LEN];
struct scatterlist sg_in;
struct crypto_blkcipher *tfm;

// This is arbitrary. it can support 2^64 inodes. Currently supporting anything larger would involve some rewriting
#define MAX_DEPTH 64 
#define NODE_LABEL_LEN 8

u8 pprf_depth = 16;

struct node_label {
	u8 bstr[NODE_LABEL_LEN];
	u8 depth;
};

struct pprf_key {
    u8 key[PRG_INPUT_LEN];
    struct node_label lbl;
};

struct pprf_key* master_key;
unsigned long master_key_first_page;
int master_key_count; // how many individual keys make up the master key
int max_master_key_count;

struct prefix_result {
	bool exact;
	int index;
};

struct prefix_result (*find_pkey_index_by_prefix) (struct node_label*);


void print_pkey(struct pprf_key* pkey);

/* Returns crypto-safe random bytes from kernel pool. 
   Taken from eraser code */
static inline void ggm_prf_get_random_bytes_kernel(u8 *data, u64 len)
{
	crypto_get_default_rng();
	crypto_rng_get_bytes(crypto_default_rng, data, len);
	crypto_put_default_rng();
}


int prg_from_aes_ctr(u8* key, u8* buf) {
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

int alloc_master_key(void) {
    if (!master_key_count) {
		// 	max_master_key_count = ((4<<10) <<10) / sizeof(struct pprf_key);
		// 	master_key = (void*)__get_free_pages(GFP_KERNEL, 10);
		max_master_key_count = 16000;
        master_key = vmalloc(sizeof(struct pprf_key)*max_master_key_count);
    }
	return 0;
}

int expand_master_key(void) {
	void* tmp = vmalloc(max_master_key_count*2*sizeof(struct pprf_key));
	if (!tmp)
		return -ENOMEM;
	memcpy(tmp, master_key, sizeof(struct pprf_key) * max_master_key_count);
	vfree(master_key);
	max_master_key_count *= 2;
	master_key = tmp;

	return 0;
}

void init_pkey_from_buf(struct pprf_key* pkey, u8* key, u8 depth, u8* node_label) {
    memcpy(pkey->key, key, PRG_INPUT_LEN);
    pkey->lbl.depth = depth;
    memcpy(pkey->lbl.bstr, node_label, NODE_LABEL_LEN);
}

void init_node_label_from_bitstring(struct node_label *lbl, const char* bitstring) {
	int i;
	memset(lbl->bstr, 0, NODE_LABEL_LEN);
	lbl->depth = strlen(bitstring);
	for (i=0; i<lbl->depth; ++i) {
		set_bit_in_buf(lbl->bstr, i, bitstring[i] == '1');
		// lbl->bstr[i/8] += (bitstring[i] == '1' ? 1 : 0) * (1 << (i%8));
	}
}

// Big endian
void init_node_label_from_long(struct node_label *lbl, u64 val, u8 depth) {
	u8 idx;

	lbl->depth = depth;
	for (idx=0; idx<depth; ++idx) {
		set_bit_in_buf(lbl->bstr, depth-1-idx, (1<<idx) & val);
	}
}

void init_pkey_from_bitstring(struct pprf_key* pkey, u8* key, const char* bitstring) {
    if (key)
		memcpy(pkey->key, key, PRG_INPUT_LEN);
	init_node_label_from_bitstring(&pkey->lbl, bitstring);
}

void init_pkey_top_level(struct pprf_key* pkey) {
    ggm_prf_get_random_bytes_kernel(pkey->key, PRG_INPUT_LEN);
    pkey->lbl.depth = 0;
}


/* Return -1 if pk1->node_label < pk2->node_label
 *		   1 if	pk1->node_label > pk2->node_label
 *		   0 if equal
 * Lexicographic order.
 * 
 * Compare bit by bit and return if any of the bits are different
 * Otherwise, one string will be a prefix of the other
 */
int compare_node_labels(const void *p1, const void *p2) {
	struct node_label *l1, *l2;
	u8 minlen;
	u8 i;
	u8 b1, b2;

	l1 = (struct node_label*) p1;
	l2 = (struct node_label*) p2;
	minlen = min(l1->depth, l2->depth);
	for (i=0; i<minlen; ++i) {
		b1 = check_bit_is_set(l1->bstr, i);
		b2 = check_bit_is_set(l2->bstr, i);
		if (b1 != b2) 
			return b1 - b2;
	}

	if (l1->depth < l2->depth)
		return -1;
	if (l1->depth > l2->depth)
		return 1;
	return 0;
}

int compare_pkeys_by_label(const void* pk1, const void* pk2) {
	return compare_node_labels(&((struct pprf_key*) pk1)->lbl, &((struct pprf_key*) pk2)->lbl);
}

// returns -1 if the label should be before the pk, etc
int compare_label_to_pkey(const void *l, const void *pk) {
	return compare_node_labels(l, &((struct pprf_key*) pk)->lbl);
}

// Return 1 if strict prefix, 0 if equal, and -1 if not prefix
int is_prefix(struct node_label *lbl, struct node_label *pre) {
	int i;
	bool b1, b2;

	if (pre->depth > lbl->depth)
		return -1;
	for (i=0; i<pre->depth; ++i) {
		b1 = check_bit_is_set(lbl->bstr, i);
		b2 = check_bit_is_set(pre->bstr, i);
		if (b1 != b2) 
			return -1;
	}
	return pre->depth == lbl->depth ? 0 : 1;
}



// puncture operation


// This returns master_key_count if its not a prefix
struct prefix_result find_pkey_index_by_prefix_linear(struct node_label *lbl) {
	int i, r;
	struct prefix_result ret;

	for (i=0; i<master_key_count; ++i) {
		r = is_prefix(lbl, &master_key[i].lbl);
		if (r == 0) {
			ret = (struct prefix_result) {true, i};
			return ret;
		}
		if (r == 1) {
			ret = (struct prefix_result) {false, i};
			return ret;
		}
	}
	ret = (struct prefix_result) {false,  master_key_count};
	return ret;
}

struct prefix_result find_pkey_index_by_prefix_bsearch(struct node_label *lbl) {
	int i, r, l, cmp, step;
	struct prefix_result ret = {false, master_key_count};

	i = -1;
	for (step = master_key_count; step >= 1; step /= 2) {
		while (i + step < master_key_count 
			&& compare_label_to_pkey(lbl, &master_key[i+step]) >= 0) {
			i += step;
		}
	} 
	cmp = is_prefix(lbl, &master_key[i].lbl);
	if (cmp == 0) {
		ret = (struct prefix_result) {true, i};
	} else if (cmp == 1) {
		ret = (struct prefix_result) {false, i};
	}
	return ret;
}




void puncture(struct node_label *lbl) {
	// 1. find root in master key
	struct prefix_result r = find_pkey_index_by_prefix(lbl);
	if (r.index == master_key_count || r.exact)
		return;

	int i = r.index;
	struct pprf_key *root = &master_key[r.index];

	// 2. find all neighbors in path
	int neighbors_cnt = pprf_depth - root->lbl.depth; 
	struct pprf_key newpkeys[neighbors_cnt];

	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	u8 n;
	bool set;

	memcpy(keycpy, root->key, PRG_INPUT_LEN);
	n = root->lbl.depth;
	while (n < pprf_depth) {
		prg_from_aes_ctr(keycpy, tmp);
		set = check_bit_is_set(lbl->bstr, n);
		if (set) {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
			memcpy(newpkeys[n - root->lbl.depth].key, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			memcpy(newpkeys[n - root->lbl.depth].key, tmp, PRG_INPUT_LEN);
		}
		memcpy(&newpkeys[n - root->lbl.depth].lbl, lbl, sizeof(struct node_label));
		set_bit_in_buf(newpkeys[n - root->lbl.depth].lbl.bstr, n, !set);
		newpkeys[n - root->lbl.depth].lbl.depth = n+1;
		// print_pkey(&newpkeys[n - root->lbl.depth]);
		++n;
	}
	// 3. insert new keys
	sort(newpkeys, neighbors_cnt, sizeof(struct pprf_key), &compare_pkeys_by_label, NULL);
	memmove(master_key + i + neighbors_cnt, master_key + i+1, sizeof(struct pprf_key) * (master_key_count - i-1));
	memcpy(master_key + i, newpkeys, sizeof(struct pprf_key) * neighbors_cnt);
	master_key_count += neighbors_cnt - 1;

	// 4. expand array if necessary (array version)
	if (master_key_count > max_master_key_count - MAX_DEPTH) 
		expand_master_key();
}

void puncture_at_tag(u64 tag) {
	struct node_label lbl;
	init_node_label_from_long(&lbl, tag, pprf_depth);
	puncture(&lbl);
}


/* PPRF evaluation
 * 	Returns -1 if the tag has been punctured
 * 	Otherwise returns 0 and out should be filled with the 
 * 	evaluation of PPRF(tag)
 */
int evaluate_at_tag(u64 tag, u8* out) {
	struct node_label lbl;
	init_node_label_from_long(&lbl, tag, pprf_depth);

	int keyidx = find_pkey_index_by_prefix(&lbl).index;
	if (keyidx == master_key_count) 
		return -1;

	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	memcpy(keycpy, master_key[keyidx].key, PRG_INPUT_LEN);

	int n = master_key[keyidx].lbl.depth;
	// printk(KERN_INFO "Begin eval: \n");
	for (; n<pprf_depth; ++n) {
		// printk(KERN_CONT " %u\n", n);
		prg_from_aes_ctr(keycpy, tmp);
		set = check_bit_is_set(lbl.bstr, n);
		if (set) {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		}
	}
	memcpy(out, keycpy, PRG_INPUT_LEN);
	return 0;
}



// printing functions

void label_to_string(struct node_label *lbl, char* node_label_str) {
    int i;
	
	if (lbl->depth == 0) {
		node_label_str[0] = '\"';
		node_label_str[1] = '\"';
		node_label_str[2] = '\0';
	} else {
		for (i=0; i<lbl->depth; ++i) {
			node_label_str[i] = check_bit_is_set(lbl->bstr, i) ? '1' : '0';
		}
		node_label_str[lbl->depth] = '\0';
	}
}

void print_pkey(struct pprf_key* pkey) {
    // terrible terrible stringy stuff
    char node_label_str[8*NODE_LABEL_LEN+1];

	label_to_string(&pkey->lbl, node_label_str);
    printk(KERN_INFO "PPRF KEY: %016ph, label: %s, depth: %d\n"
				, pkey->key, node_label_str, pkey->lbl.depth);
}

void print_label(struct node_label *lbl) {
	char node_label_str[8*NODE_LABEL_LEN+1];

	label_to_string(lbl, node_label_str);
    printk(KERN_INFO "NODE LABEL: %s, depth: %d\n", node_label_str, lbl->depth);
}

void print_master_key(void) {
	int i;

	printk(KERN_INFO ": Master key dump START:\n");
	for (i=0; i<master_key_count; ++i) 
		print_pkey(&master_key[i]);

	printk(KERN_INFO ": END Master key dump\n");

}


// tests

void test_print_pkey(void) {
	struct pprf_key pkey;
	pkey.lbl.depth = 8;
	pkey.lbl.bstr[0] = 255;

	print_pkey(&pkey);
	
}

void test_init_pkey_from_bitstring_and_compare(void) {
	char *twobitstrings[7] = {"", "0", "00", "01", "1", "10", "11"};
	struct pprf_key pkeys[7];
	u8 n,m;
	int c;
	u8 key[PRG_INPUT_LEN];

	for(n=0; n<7; ++n) {
		ggm_prf_get_random_bytes_kernel(key, PRG_INPUT_LEN);
		init_pkey_from_bitstring(&pkeys[n], key, twobitstrings[n]);
		print_pkey(&pkeys[n]);
	}

	for(n=0; n<7; ++n) {
		for (m=0; m<7; ++m) {
			c = compare_pkeys_by_label(&pkeys[n], &pkeys[m]);
			printk(KERN_INFO "\t Compare: %s %s %s\n", twobitstrings[n], 
					c ? (c == 1 ? ">" : "<")
					: "=", twobitstrings[m]);
		}
	}
}

void test_sort_lexicographic(void) {
	char *twobitstrings[7] = {"", "0", "00", "01", "1", "10", "11"};
	struct pprf_key pkeys[7];
	u8 n;
	u8 key[PRG_INPUT_LEN];

	u8 order1[7] = {1, 4, 2, 0, 5, 3, 6};
	
	printk(KERN_INFO ": Initial order\n");
	for(n=0; n<7; ++n) {
		ggm_prf_get_random_bytes_kernel(key, PRG_INPUT_LEN);
		// printk(KERN_INFO "%s\n", twobitstrings[n]);
		init_pkey_from_bitstring(&pkeys[n], key, twobitstrings[order1[n]]);
		print_pkey(&pkeys[n]);
	}

	sort(pkeys, 7, sizeof(struct pprf_key), &compare_pkeys_by_label, NULL);

	printk(KERN_INFO ": Sorted order\n");
	for (n=0; n<7; ++n) {
		print_pkey(&pkeys[n]);
	}
}

void test_find_prefix(void) {
	struct node_label nlbl;
	init_pkey_from_bitstring(master_key, NULL, "0");
	init_pkey_from_bitstring(master_key+1, NULL, "11");
	master_key_count = 2;

	init_node_label_from_bitstring(&nlbl, "01");

	int idx = find_pkey_index_by_prefix(&nlbl).index;
	struct pprf_key *root = master_key+idx;
	printk(KERN_INFO "ROOT: %p\n", root);
	if (root)
		print_pkey(root);
}

void test_puncture_0(void) {
	struct node_label punct_node;

	init_pkey_top_level(&master_key[0]);
	master_key_count = 1;
	print_master_key();
	printk(KERN_INFO "Setting pprf depth = 2\n");
	pprf_depth = 2;

	printk(KERN_INFO "Puncturing 10...\n");
	init_node_label_from_bitstring(&punct_node, "10");
	puncture(&punct_node);
	print_master_key();

	printk(" ... resetting...\n");

	init_pkey_top_level(&master_key[0]);
	master_key_count = 1;
	print_master_key();

	printk(KERN_INFO "Puncturing 01...\n");
	init_node_label_from_bitstring(&punct_node, "01");
	puncture(&punct_node);
	print_master_key();

	printk(KERN_INFO "Puncturing 10...\n");
	init_node_label_from_bitstring(&punct_node, "10");
	puncture(&punct_node);
	print_master_key();

	printk(KERN_INFO "Puncturing 01 again...\n");
	init_node_label_from_bitstring(&punct_node, "01");
	puncture(&punct_node);
	print_master_key();

}

void test_puncture_1(void) {
	struct node_label punct_node;

	init_pkey_top_level(&master_key[0]);
	master_key_count = 1;
	print_master_key();
	printk(KERN_INFO "Setting pprf depth = 16\n");
	pprf_depth = 16;

	printk(KERN_INFO "Puncturing tag=0...\n");
	init_node_label_from_long(&punct_node, 0, pprf_depth);
	puncture(&punct_node);
	print_master_key();

	printk(KERN_INFO "Puncturing tag=1...\n");
	init_node_label_from_long(&punct_node, 1, pprf_depth);
	puncture(&punct_node);
	print_master_key();

	printk(KERN_INFO "Puncturing tag=2...\n");
	init_node_label_from_long(&punct_node, 2, pprf_depth);
	puncture(&punct_node);
	print_master_key();

	printk(KERN_INFO "Puncturing tag=65535...\n");
	init_node_label_from_long(&punct_node, (1<<16)-1, pprf_depth);
	puncture(&punct_node);
	print_master_key();
}


void test_evaluate_0(void) {
	init_pkey_top_level(&master_key[0]);
	master_key_count = 1;
	print_master_key();
	printk(KERN_INFO "Setting pprf depth = 16\n");
	pprf_depth = 16;

	int r;

	u8 out[PRG_INPUT_LEN];
	r = evaluate_at_tag(0, out);
	printk(KERN_INFO "Evaluation at tag 0: %s (%016ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(255, out);
	printk(KERN_INFO "Evaluation at tag 255: %s (%016ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);

	printk(KERN_INFO "Puncturing tag=1...\n");
	puncture_at_tag(1);
	print_master_key();

	r = evaluate_at_tag(0, out);
	printk(KERN_INFO "Evaluation at tag 0: %s (%016ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(1, out);
	printk(KERN_INFO "Evaluation at tag 1: %s (%016ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
	r = evaluate_at_tag(255, out);
	printk(KERN_INFO "Evaluation at tag 255: %s (%016ph)\n", r == 0?"SUCCESS" :"PUNCTURED", out);
}

void run_tests(void) {
	printk(KERN_INFO "\n running test_print_pkey\n");
	test_print_pkey();
	printk(KERN_INFO "\n running test_init_pkey_from_bitstring_and_compare\n");
	test_init_pkey_from_bitstring_and_compare();
	printk(KERN_INFO "\n running test_sort_lexicographic\n");
	test_sort_lexicographic();

	printk(KERN_INFO "\n running test_find_prefix\n");
	test_find_prefix();
	
	printk(KERN_INFO "\n running test_puncture_0\n");
	test_puncture_0();	
	printk(KERN_INFO "\n running test_puncture_1\n");
	test_puncture_1();

	printk(KERN_INFO "\n running test_evaluate_0\n");
	test_evaluate_0();

	printk(KERN_INFO "\n tests complete\n");

}


// Some preliminary benchmarking

void evaluate_n_times(u64* tag_array, int count) {
	int n;
	u64 nsstart, nsend;

	ggm_prf_get_random_bytes_kernel((u8*) tag_array, sizeof(u64)*count);
	printk(KERN_INFO "Begin evaluation: keylength = %u\n", master_key_count);
	nsstart = ktime_get_ns();
	for(n=0; n<count; ++n) {
		u8 out[PRG_INPUT_LEN];
		evaluate_at_tag(tag_array[n], out);
	}
	nsend = ktime_get_ns();
	printk(KERN_INFO /*"Time: %llu us\n"*/"Time per eval: %d us\n", /*(nsend-nsstart)/1000, */(nsend-nsstart)/1000/count);
}

void puncture_n_times(u64* tag_array, int count) {
	int n;
	u64 nsstart, nsend;

	ggm_prf_get_random_bytes_kernel((u8*) tag_array, count*sizeof(u64));
	printk(KERN_INFO "Puncturing %u times:\n", count);
	nsstart = ktime_get_ns();
	for (n=0; n<count; ++n) {
		puncture_at_tag(tag_array[n]);
	}
	nsend = ktime_get_ns();
	printk(KERN_INFO /*"Time: %llu us\n"*/"Time per puncture: %d us\n", /*(nsend-nsstart)/1000, */(nsend-nsstart)/1000/count);
}

void preliminary_benchmark_cycle(void) {
	init_pkey_top_level(&master_key[0]);
	master_key_count = 1;
	pprf_depth = 64;

	int maxcount = 10000;
	int count;
	
	u64 *tag_array;
	tag_array = kmalloc_array(maxcount, sizeof(long), GFP_KERNEL);

	evaluate_n_times(tag_array, maxcount);
	puncture_n_times(tag_array, 100);
	evaluate_n_times(tag_array, maxcount);
	puncture_n_times(tag_array, 400);
	evaluate_n_times(tag_array, maxcount);
	puncture_n_times(tag_array, 500);
	evaluate_n_times(tag_array, maxcount);
	puncture_n_times(tag_array, 1000);
	evaluate_n_times(tag_array, maxcount);
	// Getting OOM
	puncture_n_times(tag_array, 3000);
	evaluate_n_times(tag_array, maxcount);
	puncture_n_times(tag_array, 5000);
	evaluate_n_times(tag_array, maxcount);


	kfree(tag_array);
}

void preliminary_benchmark(void) {	
	find_pkey_index_by_prefix = find_pkey_index_by_prefix_linear;
	printk(KERN_INFO "  Benchmark for linear search");
	preliminary_benchmark_cycle();
	
	find_pkey_index_by_prefix = find_pkey_index_by_prefix_bsearch;
	printk(KERN_INFO "  Benchmark for binary search");
	preliminary_benchmark_cycle();
}

// kernel mod init/exit functions

static int __init ggm_pprf_init(void) {
	ggm_prf_get_random_bytes_kernel(iv, PRG_INPUT_LEN);
    (void) alloc_master_key();
    init_pkey_top_level(&master_key[0]);
	find_pkey_index_by_prefix = find_pkey_index_by_prefix_bsearch;


	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	sg_init_one(&sg_in, aes_input, 2*PRG_INPUT_LEN);

	printk(KERN_INFO "ggm pprf testing module loaded.\nIV = %016ph\n", iv);
    print_pkey(&master_key[0]);



	// run_tests();

	printk(KERN_INFO "\n BENCHMARKS \n\n");

	preliminary_benchmark();

	return 0;
}

static void __exit ggm_pprf_exit(void) {
	crypto_free_blkcipher(tfm);
    vfree(master_key);
	printk(KERN_INFO "ggm pprf testing module unloaded\n");

}


module_init(ggm_pprf_init);
module_exit(ggm_pprf_exit);

MODULE_AUTHOR("wittmann");
MODULE_DESCRIPTION("Testing for GGM PRF");
MODULE_LICENSE("GPL");
