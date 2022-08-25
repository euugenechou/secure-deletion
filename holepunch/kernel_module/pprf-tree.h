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

#ifdef HOLEPUNCH_DEBUG
struct node_label {
	u64 label;
	u8 depth;
};
#endif

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
	u8 type;
#ifdef HOLEPUNCH_DEBUG
	struct node_label lbl;
#endif
};

int alloc_master_key(struct pprf_keynode **master_key, u32 *max_master_key_count,
		unsigned len);
void init_master_key(struct pprf_keynode *master_key, u32 *master_key_count,
		unsigned len);

int puncture_at_tag(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
	u32 *pprf_size, u64 tag);
int evaluate_at_tag(struct pprf_keynode *pprf, u8 pprf_depth, prg p, void *data,
	u64 tag, u8* key);

#ifdef HOLEPUNCH_DEBUG
void label_to_string(struct node_label *lbl, char *node_label);
void dump_key(u8 *key, char *name);
void print_pprf(struct pprf_keynode *pprf, u32 pprf_size);
#endif

#ifdef PPRF_TEST
void run_tests(void);
#endif

#ifdef PPRF_TIME
void preliminary_benchmark(void);
#endif


#endif
