#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <crypto/rng.h>


#define PRG_INPUT_LEN 16
#define DEBUG 1

u8 aes_input[2*PRG_INPUT_LEN] = "\000\001\002\003\004\005\006\007"
								"\010\011\012\013\014\015\016\017"
								"\020\021\022\023\024\025\026\027"
								"\030\031\032\033\034\035\036\037";
u8 iv[PRG_INPUT_LEN];
u8 key[PRG_INPUT_LEN];
struct scatterlist sg_in;
struct crypto_blkcipher *tfm;


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

void ggm_prf(u8* in, u8* out) {
	u8 keycpy[PRG_INPUT_LEN];
	u8 tmp[2*PRG_INPUT_LEN];
	memcpy(keycpy, key, PRG_INPUT_LEN);
	u8 n;
	n = 0;
	while (n<8*PRG_INPUT_LEN) {
		prg_from_aes_ctr(keycpy, tmp);
		if (check_bit_is_set(in, n)) {
			memcpy(keycpy, tmp, PRG_INPUT_LEN);
		} else {
			memcpy(keycpy, tmp+PRG_INPUT_LEN, PRG_INPUT_LEN);
		}
// #ifdef DEBUG
		printk(KERN_INFO "At round %u: tmp = %032ph,\n\t\t bit=%u, next key = %016ph", n, tmp, check_bit_is_set(in,n), keycpy);
// #endif
		++n;
	}
	memcpy(out, keycpy, PRG_INPUT_LEN);
}


void test_prg(void) {
	u8 x[PRG_INPUT_LEN] = "\000\000\000\000\000\000\000\000"
						  "\000\000\000\000\000\000\000\000";
	u8 c[2*PRG_INPUT_LEN];
	int ret = prg_from_aes_ctr(x, c);
	printk(KERN_INFO "RET=%u prg input: %016ph\n", ret, x);
	printk(KERN_INFO "prg output: %032ph\n", c);
	printk(KERN_INFO "prg test complete\n");

}

void test_check_bit_is_set(void) {
	// u8 tst[2] = "\377\100";
	u8 tst[2] = {255, 64};
	int i=0;
	printk(KERN_INFO "Begin check bit test:");
	for (;i<16;++i) {
		printk(KERN_CONT "%u ", check_bit_is_set(tst, i));
	}
	printk(KERN_INFO "Check bit test complete\n");
}

void test_prf(void) {
	u8 in[PRG_INPUT_LEN] = "\000\000\000\000\000\000\000\000"
						   "\000\000\000\000\000\000\000\000";
	u8 out[PRG_INPUT_LEN];
	ggm_prf(in, out);
}


static int __init ggm_prf_init(void) {
	ggm_prf_get_random_bytes_kernel(iv, PRG_INPUT_LEN);
	ggm_prf_get_random_bytes_kernel(key, PRG_INPUT_LEN);
	// iv = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000";
	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	sg_init_one(&sg_in, aes_input, 2*PRG_INPUT_LEN);

	printk(KERN_INFO "ggm prf testing module loaded.\nIV = %016ph\nkey = %016ph", iv, key);
	// int i;
	// for (i=0; i<16; ++i) 
	// 	printk(KERN_CONT "(%d)%x ", i, iv[i]);

	test_prg();
	test_check_bit_is_set();
	test_prf();

	return 0;
}

static void __exit ggm_prf_exit(void) {
	crypto_free_blkcipher(tfm);
	printk(KERN_INFO "ggm prf testing module unloaded\n");

}


module_init(ggm_prf_init);
module_exit(ggm_prf_exit);

MODULE_AUTHOR("wittmann");
MODULE_DESCRIPTION("Testing for GGM PRF");
MODULE_LICENSE("GPL");
