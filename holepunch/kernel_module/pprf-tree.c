#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/fs.h>

#include "pprf-tree.h"

#ifdef TIME
#include <linux/timekeeping.h>
#endif


struct scatterlist sg_in;
struct crypto_blkcipher *tfm;


void reset_pprf_keynode(struct pprf_keynode *node) {
	memset(node, 0, sizeof(struct pprf_keynode));
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

int alloc_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count, unsigned len) {
	*max_master_key_count = len / (sizeof(struct pprf_keynode));
	if (*master_key) {
		vfree(*master_key);
	}
	*master_key = vmalloc(len);

	return (*master_key != NULL);
}


int expand_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count, unsigned factor) {
	struct pprf_keynode *tmp;
#ifdef HOLEPUNCH_DEBUG
	printk("RESIZING: current capacity = %u\n", *max_master_key_count);
#endif	
	tmp = vmalloc((*max_master_key_count)*factor*sizeof(struct pprf_keynode));
	if (!tmp)
		return -ENOMEM;
	memcpy(tmp, *master_key, sizeof(struct pprf_keynode) * (*max_master_key_count));
	vfree(*master_key);
	*max_master_key_count *= factor;
	*master_key = tmp;
#ifdef HOLEPUNCH_DEBUG
	printk("RESIZING DONE: final capacity = %u\n", *max_master_key_count);
#endif	

	return 0;
}

/* we may need to zero out more than just the master key because of things
 * like page-granularity writes
 */
void init_master_key(struct pprf_keynode *master_key, u32 *master_key_count, unsigned len) {
	memset(master_key, 0, len);
    ggm_prf_get_random_bytes_kernel(master_key->key, PRG_INPUT_LEN);
	*master_key_count = 1;
}

void init_node_label_from_bitstring(struct node_label*lbl, const char* bitstring) {
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

// void init_node_label_from_long(struct node_label*lbl, u64 u) {
// 	__be64 bigendian = cpu_to_be64(u);
// 	memcpy(lbl->bstr, (u8*) &bigendian, NODE_LABEL_LEN);
// 	lbl->depth = pprf_depth;
// }


/* Tree traversal
 *
 * Returns ptr to key or NULL if punctured
 * Additionally will write the node index to "index" if not NULL
 * Will initialize depth to 0
 */ 
struct pprf_keynode *find_key(struct pprf_keynode *pprf_base, u8 pprf_depth, 
		struct node_label *lbl, u32 *depth, int *index) {
	unsigned i;
	struct pprf_keynode *cur;
	
	i = 0;
	*depth = 0;
	do {
		cur = pprf_base + i;
		if (likely(index)) {
			*index = i;
		}
		if(check_bit_is_set(lbl->bstr, *depth)) 
			i = cur->ir;
		else
			i = cur->il;
		if (i == 0) 
			return cur;
		// else if (i == (u32)-1)
		// 	return NULL;
		++*depth;
	} while (*depth < pprf_depth);

	cur = pprf_base + i;
	if (cur->il == 0) {
		return cur;
	}
	return NULL;
}

/* PPRF puncture operation
 * 
 * Returns -1 if the puncture was not possible (eg if a puncture
 * at that tag had already been executed)
 * Otherwise returns the index of the PPRF keynode that was changed
 * as a result of the puncture (used for writeback purposes).
 */
int puncture(struct pprf_keynode *pprf_base, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u32 *master_key_count, u32 *max_master_key_count, struct node_label*lbl) {
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	int root_index;
	struct pprf_keynode *root;
	
	root = find_key(pprf_base, pprf_depth, lbl, &depth, &root_index);
	
	// it will be NULL if its already been punctured, in which case we just return
	if (!root) {
		// printk(KERN_INFO "Should not be reached\n");
		return -1;
	}

	// now we traverse
	// 2. find all neighbors in path

	memcpy(keycpy, root->key, PRG_INPUT_LEN);
	memset(root->key, 0, PRG_INPUT_LEN);
	while (depth < pprf_depth) {
		prg_from_aes_ctr(keycpy, iv, tfm, tmp);
		set = check_bit_is_set(lbl->bstr, depth);
		if (set) {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			memcpy((pprf_base + *master_key_count)->key, tmp, PRG_INPUT_LEN);
			root->il = *master_key_count;
			root->ir = *master_key_count+1;
		} else {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
			memcpy((pprf_base + *master_key_count)->key, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
			root->ir = *master_key_count;
			root->il = *master_key_count+1;
		}
	#ifdef HOLEPUNCH_DEBUG
		memcpy(&(pprf_base+*master_key_count)->lbl, lbl, sizeof(struct node_label));
		set_bit_in_buf((pprf_base+*master_key_count)->lbl.bstr, depth, !set);
		(pprf_base + *master_key_count)->lbl.depth = depth+1;

		memcpy(&(pprf_base+*master_key_count)->lbl, lbl, sizeof(struct node_label));
		set_bit_in_buf((pprf_base + *master_key_count+1)->lbl.bstr, depth, set);
		(pprf_base + *master_key_count+1)->lbl.depth = depth+1;
	#endif
		(pprf_base + *master_key_count)->il = 0;
		(pprf_base + *master_key_count)->ir = 0;
		*master_key_count += 2;
		++depth;
		root = (pprf_base + *master_key_count-1);
	}
	// At the end of the loop, the root node is always a punctured node. So set links accordingly
	root->il = -1;
	root->ir = -1;	
	
	return root_index;
}

int puncture_at_tag(struct pprf_keynode *pprf_base, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u32 *master_key_count, u32 *max_master_key_count, u64 tag) {
	struct node_label lbl;
	init_node_label_from_long(&lbl, pprf_depth, tag);

	return puncture(pprf_base, iv, tfm, pprf_depth,
			master_key_count, max_master_key_count, &lbl);
}


/* PPRF evaluation
 * 	Returns -1 if the tag has been punctured
 * 	Otherwise returns 0 and out should be filled with the 
 * 	evaluation of PPRF(tag)
 */
int evaluate(struct pprf_keynode *pprf_base, u8* iv, struct crypto_blkcipher *tfm,
		u8 pprf_depth, struct node_label *lbl, u8 *out) {
	u32 depth;
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	bool set;
	struct pprf_keynode *root; 
	
#ifdef HOLEPUNCH_DEBUG
	memset(out, 0xcc, PRG_INPUT_LEN);
#endif

	root = find_key(pprf_base, pprf_depth, lbl, &depth, NULL);
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


int evaluate_at_tag(struct pprf_keynode *pprf_base, u8* iv, struct crypto_blkcipher *tfm, 
		u8 pprf_depth, u64 tag, u8* out) {
	struct node_label lbl;
	init_node_label_from_long(&lbl, pprf_depth, tag);

	return evaluate(pprf_base, iv, tfm, pprf_depth, &lbl, out);
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
			bit = check_bit_is_set(lbl->bstr, i);
			node_label_str[i] = bit ? '1' : '0';
			// value += bit << i;
		}
		// snprintf(node_label_str + lbl->depth + 1, len - lbl->depth, "(%llu)", value);
	}
}

// prints the key that evaluates this label (or none if punctured)
// void print_pkeynode_HOLEPUNCH_DEBUG(struct pprf_keynode *master_key, u8 pprf_depth, struct node_label*lbl) {
//     // terrible terrible stringy stuff
// 	int depth;
//     char node_label_str[8*NODE_LABEL_LEN+21];
// 	struct pprf_keynode *pkey;

// 	label_to_string(lbl, node_label_str, 8*NODE_LABEL_LEN+21);
// 	pkey = find_key(master_key, pprf_depth, lbl, &depth, NULL);

// 	printk(" Finding key for label %s ...\n", node_label_str);
// 	if (pkey) {
// 		label_to_string(&pkey->lbl, node_label_str, 8*NODE_LABEL_LEN+21);
// 		printk(KERN_INFO "PPRF KEY: %16ph, label: %s, depth: %d\n"
// 				, pkey->key, node_label_str, pkey->lbl.depth);
// 	} else {
// 		printk(KERN_INFO "Key not present\n");
// 	}    
// }


void print_master_key(struct pprf_keynode *pprf_base, u32 *master_key_count) {
	u32 i;
	struct pprf_keynode *node;
	char node_label_str[8*NODE_LABEL_LEN+1];
	
	printk(KERN_INFO ": Master key dump START, len=%u:\n", *master_key_count);
	i=0;
	for (; i<*master_key_count; ++i) {
		node = (pprf_base + i);
		label_to_string(&node->lbl, node_label_str, 8*NODE_LABEL_LEN+1);
		// trace_printk(KERN_INFO "n:%u, il:%u, ir:%u, key:%16ph, label:%s\n",
		// 	i, node->il, node->ir, node->key, node_label_str);
		printk(KERN_INFO "n:%u, ", i);
		printk(KERN_CONT "il:%u, ", node->il);
		printk(KERN_CONT "ir:%u, ", node->ir);
		printk(KERN_CONT "key:%16ph, ", node->key);
		printk(KERN_CONT "label:%s\n", node_label_str);
	}

	printk(KERN_INFO ": END Master key dump\n");

}

#endif