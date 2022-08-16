#ifndef PPRF_TREE
#define PPRF_TREE

#include <linux/types.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/rng.h>

#define PRG_INPUT_LEN 32

typedef void (*prg) (void *, u8 *, u8 *);

/* Return crypto-safe random data from kernel pool. */
static inline void kernel_random(u8 *data, u64 len)
{
	crypto_get_default_rng();
	crypto_rng_get_bytes(crypto_default_rng, data, len);
	crypto_put_default_rng();
}

// This is arbitrary. it can support 2^64 inodes. Currently supporting anything larger would involve some rewriting
#define MAX_DEPTH 64
#define NODE_LABEL_LEN (MAX_DEPTH+7)/8


struct node_label {
	u64 label;
	u8 depth;
};

/* Binary-tree based organization of the PPRF keys
 * 	
 * We lay out the tree in an array consisting of
 * 	{il, ir, key[len]} triples
 * il: index where the left child is stored
 * ir: index where the right child is stored
 * key: value of the PPRF key (only meaningful for leaf nodes)
 * 
 * two sentinel indices
 * 0: this is a leaf node
 * -1: the subtree has been punctured
 * 
 * root node is placed at index 0
 * 
 * In particular I /don't/ think we need to store depth information
 * in this implementation because the depth matches the depth in the
 * tree exactly
 */

enum {
	PPRF_INTERNAL = 0,
	PPRF_KEYLEAF,
	PPRF_PUNCTURE,
};

struct __attribute__((packed)) pprf_keynode {
	union {
		struct {
			u32 il;
			u32 ir;
		} next;
		u8 key[PRG_INPUT_LEN];
	} v;
	u8 flag;
#ifdef HOLEPUNCH_DEBUG
	struct node_label lbl;
#endif
};

void reset_pprf_keynode(struct pprf_keynode *node);

inline bool check_bit_is_set(u64 tag, u8 index);
inline void set_bit_in_buf(u64 *tag, u8 index, bool val);

int alloc_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count, 
		unsigned len);
int expand_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count, 
		unsigned factor);
void init_master_key(struct pprf_keynode *master_key, u32 *master_key_count, 
		unsigned len);

void init_node_label_from_long(struct node_label *lbl, u8 pprf_depth, u64 val);

struct pprf_keynode *find_key(struct pprf_keynode *pprf_base, u8 pprf_depth,
		u64 tag, u32 *depth, int *index) ;
int puncture(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data,
	u32 *master_key_count, u32 *max_master_key_count, u64 tag);
int puncture_at_tag(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data,
	u32 *master_key_count, u32 *max_master_key_count, u64 tag);
int evaluate(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data, u64 tag, u8 *out);
int evaluate_at_tag(struct pprf_keynode *pprf_base, u8 pprf_depth, prg p, void *data, u64 tag, u8* out);

#ifdef HOLEPUNCH_DEBUG
void label_to_string(struct node_label *lbl, char* node_label_str, u16 len);
void print_pkeynode_debug(struct pprf_keynode *master_key, u8 pprf_depth, struct node_label *lbl);
void print_master_key(struct pprf_keynode *pprf_base, u32 *master_key_count);
#endif

#ifdef HOLEPUNCH_PPRF_TEST
void run_tests(void);
#endif
#ifdef HOLEPUNCH_PPRF_TIME
void preliminary_benchmark(void);
#endif


#endif
