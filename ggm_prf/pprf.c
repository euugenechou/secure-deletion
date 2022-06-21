#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <crypto/rng.h>
#include <linux/sort.h>

#define PRG_INPUT_LEN 16

u8 aes_input[2*PRG_INPUT_LEN] = "\000\001\002\003\004\005\006\007"
								"\010\011\012\013\014\015\016\017"
								"\020\021\022\023\024\025\026\027"
								"\030\031\032\033\034\035\036\037";

u8 iv[PRG_INPUT_LEN];
// u8 key[PRG_INPUT_LEN];
struct scatterlist sg_in;
struct crypto_blkcipher *tfm;

// This is arbitrary. it can support 2^56 inodes
#define MAX_DEPTH 56 
#define NODE_LABEL_LEN 7

struct pprf_key {
    u8 key[PRG_INPUT_LEN];
    u8 node_label[NODE_LABEL_LEN];
    u8 depth;
};

struct pprf_key* master_key;
int master_key_count; // how many individual keys make up the master key




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

void ggm_prf(u8* in, u8* out, struct pprf_key* pkey) {
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	u8 n;

	memcpy(keycpy, pkey->key, PRG_INPUT_LEN);
	n = 0;
	while (n < MAX_DEPTH - pkey->depth) {
		prg_from_aes_ctr(keycpy, tmp);
		if (check_bit_is_set(in, n)) {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		}
// #ifdef DEBUG
		printk(KERN_INFO "At round %u/%u: tmp = %032ph,\n\t\t bit=%u, next key = %016ph", 
                n, pkey->depth, tmp, check_bit_is_set(in,n), keycpy);
// #endif
		++n;
	}
	memcpy(out, keycpy, PRG_INPUT_LEN);
}



int alloc_master_key(void) {
    if (!master_key_count) {
        master_key = kmalloc_array(2000, sizeof(struct pprf_key), GFP_KERNEL);
    }
}

void init_pkey_from_buf(struct pprf_key* pkey, u8* key, u8 depth, u8* node_label) {
    memcpy(pkey->key, key, PRG_INPUT_LEN);
    pkey->depth = depth;
    memcpy(pkey->node_label, node_label, NODE_LABEL_LEN);
}

void init_pkey_from_bitstring(struct pprf_key* pkey, u8* key, char* bitstring) {
	int len;
	int i;

    memcpy(pkey->key, key, PRG_INPUT_LEN);
	pkey->depth = strlen(bitstring);
	for (i=0; i<pkey->depth; ++i) {
		pkey->node_label[i/8] += (bitstring[i] == '1' ? 1 : 0) * (1 << (i%8));
	}

}

void init_pkey_top_level(struct pprf_key* pkey) {
    ggm_prf_get_random_bytes_kernel(pkey->key, PRG_INPUT_LEN);
    pkey->depth = 0;
}


/* Return -1 if pk1->node_label < pk2->node_label
 *		   1 if	pk1->node_label > pk2->node_label
 *		   0 if equal
 * Lexicographic order.
 * 
 * Compare bit by bit and return if any of the bits are different
 * Otherwise, one string will be a prefix of the other
 */
int compare_pkeys_by_label(struct pprf_key* pk1, struct pprf_key* pk2) {
	u8 minlen;
	u8 i;
	u8 b1, b2;

	minlen = min(pk1->depth, pk2->depth);
	for (i=0; i<minlen; ++i) {
		b1 = check_bit_is_set(pk1->node_label, i);
		b2 = check_bit_is_set(pk2->node_label, i);
		if (b1 != b2) 
			return b1 - b2;
	}

	if (pk1->depth < pk2->depth)
		return -1;
	if (pk1->depth > pk2->depth)
		return 1;
	return 0;
}


// convenience functions



// printing functions

void print_pkey(struct pprf_key* pkey) {
    // terrible terrible stringy stuff
    char node_label_str[8*NODE_LABEL_LEN+1];
    int i;

	memset(node_label_str, '\0', 8*NODE_LABEL_LEN+1);
    for (i=0; i<pkey->depth; ++i) {
        node_label_str[i] = check_bit_is_set(pkey->node_label, i) ? '1' : '0';
    }
    node_label_str[i] = '\0';
    printk(KERN_INFO "PPRF KEY: %016ph, label: %s, depth: %d\n", pkey->key, node_label_str, pkey->depth);
}




// tests

void test_print_pkey(void) {
	struct pprf_key pkey;
	pkey.depth = 8;
	pkey.node_label[0] = 255;

	print_pkey(&pkey);
	
}

void test_init_pkey_from_bitstring_and_compare(void) {
	char *twobitstrings[6] = {"0", "00", "01", "1", "10", "11"};
	struct pprf_key pkeys[6];
	u8 n,m;
	int c;
	u8 key[PRG_INPUT_LEN];

	for(n=0; n<6; ++n) {
		ggm_prf_get_random_bytes_kernel(key, PRG_INPUT_LEN);
		init_pkey_from_bitstring(&pkeys[n], key, twobitstrings[n]);
		print_pkey(&pkeys[n]);
	}

	for(n=0; n<6; ++n) {
		for (m=0; m<6; ++m) {
			c = compare_pkeys_by_label(&pkeys[n], &pkeys[m]);
			printk(KERN_INFO "\t Compare: %s %s %s\n", twobitstrings[n], 
					c ? (c == 1 ? ">" : "<")
					: "=", twobitstrings[m]);
		}
	}
}


void test_sort_lexicographic(void) {
	
}


void run_tests(void) {
	printk(KERN_INFO "running test_print_pkey");
	test_print_pkey();
	printk(KERN_INFO "running test_init_pkey_from_bitstring_and_compare");
	test_init_pkey_from_bitstring_and_compare();

}


// kernel mod init/exit functions

static int __init ggm_pprf_init(void) {
	ggm_prf_get_random_bytes_kernel(iv, PRG_INPUT_LEN);
    (void) alloc_master_key();
    init_pkey_top_level(&master_key[0]);

	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	sg_init_one(&sg_in, aes_input, 2*PRG_INPUT_LEN);

	printk(KERN_INFO "ggm pprf testing module loaded.\nIV = %016ph\n", iv);
    print_pkey(&master_key[0]);



	run_tests();

	return 0;
}

static void __exit ggm_pprf_exit(void) {
	crypto_free_blkcipher(tfm);
    kfree(master_key);
	printk(KERN_INFO "ggm pprf testing module unloaded\n");

}


module_init(ggm_pprf_init);
module_exit(ggm_pprf_exit);

MODULE_AUTHOR("wittmann");
MODULE_DESCRIPTION("Testing for GGM PRF");
MODULE_LICENSE("GPL");
