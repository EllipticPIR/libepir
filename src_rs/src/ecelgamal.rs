use std::convert::{TryFrom, TryInto};
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsBasepointTable;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

const SCALAR_SIZE: usize = 32;
const POINT_SIZE : usize = 32;
const CIPHER_SIZE: usize = 2 * POINT_SIZE;
const DEFAULT_MMAX_MOD: u8 = 24;
const DEFAULT_MMAX: usize = 1 << DEFAULT_MMAX_MOD;

fn format_as_hex(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    for i in 0..bytes.len() {
        write!(f, "{:02x}", bytes[i])?;
    }
    Ok(())
}

pub fn random_scalar() -> Scalar {
    let mut csprng = OsRng;
    Scalar::random(&mut csprng)
}

pub struct Cipher {
    c1: CompressedEdwardsY,
    c2: CompressedEdwardsY,
}

pub struct EncryptionContext {
    table: EdwardsBasepointTable,
}

impl EncryptionContext {
    pub fn new() -> Self {
        Self {
            table: EdwardsBasepointTable::create(&ED25519_BASEPOINT_POINT),
        }
    }
}

pub trait Encrypt {
    fn encrypt(&self, enc_ctx: &EncryptionContext, msg: &Scalar, r: Option<&Scalar>) -> Cipher;
}

#[derive(Debug)]
pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    pub fn new() -> Self {
        Self {
            scalar: random_scalar(),
        }
    }
}

impl From<[u8; SCALAR_SIZE]> for PrivateKey {
    fn from(buf: [u8; SCALAR_SIZE]) -> Self {
        Self {
            scalar: Scalar::from_bits(buf),
        }
    }
}

impl Encrypt for PrivateKey {
    fn encrypt(&self, enc_ctx: &EncryptionContext, msg: &Scalar, r: Option<&Scalar>) -> Cipher {
        let rr = match r {
            Some(r) => *r,
            None => random_scalar(),
        };
        Cipher{
            c1: enc_ctx.table.basepoint_mul(&rr).compress(),
            c2: enc_ctx.table.basepoint_mul(&(&rr * self.scalar + msg)).compress(),
        }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.scalar == other.scalar
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.scalar.as_bytes();
        format_as_hex(f, bytes)
    }
}

#[derive(Debug)]
pub struct PublicKey {
    point: EdwardsPoint,
}

impl PublicKey {
    pub fn new(privkey: &PrivateKey) -> Self {
        Self {
            point: privkey.scalar * ED25519_BASEPOINT_POINT,
        }
    }
}

impl TryFrom<[u8; POINT_SIZE]> for PublicKey {
    type Error = ();
    fn try_from(buf: [u8; POINT_SIZE]) -> Result<Self, Self::Error> {
        let point = CompressedEdwardsY::from_slice(&buf).decompress();
        match point {
            Some(point) => Ok(Self { point }),
            None => Err(()),
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Encrypt for PublicKey {
    fn encrypt(&self, enc_ctx: &EncryptionContext, msg: &Scalar, r: Option<&Scalar>) -> Cipher {
        let rr = match r {
            Some(r) => *r,
            None => random_scalar(),
        };
        Cipher{
            c1: enc_ctx.table.basepoint_mul(&rr).compress(),
            c2: (&rr * self.point + enc_ctx.table.basepoint_mul(msg)).compress(),
        }
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let compressed = self.point.compress();
        let bytes = compressed.as_bytes();
        format_as_hex(f, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVKEY: [u8; SCALAR_SIZE] = [
        0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
        0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
        0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
        0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07,
    ];
    const PUBKEY: [u8; POINT_SIZE] = [
        0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
        0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
        0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
        0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8,
    ];
    const MSG: u64 = (0x12345678 & (DEFAULT_MMAX - 1)) as u64;
    const R: [u8; SCALAR_SIZE] = [
        0x42, 0xff, 0x2d, 0x98, 0x4a, 0xe5, 0xa2, 0x8f,
        0x7d, 0x02, 0x69, 0x87, 0xc7, 0x10, 0x9a, 0x7b,
        0x3a, 0x1d, 0x36, 0x58, 0x82, 0x5a, 0x09, 0x17,
        0xe1, 0x69, 0x3e, 0x83, 0xa5, 0x71, 0x5d, 0x09,
    ];
    const CIPHER: [u8; CIPHER_SIZE] = [
        0x11, 0xa9, 0x4e, 0xb7, 0x18, 0x53, 0x7e, 0x94,
        0x7d, 0x0f, 0xf3, 0x0c, 0xdd, 0xae, 0x16, 0xae,
        0xab, 0x42, 0x9e, 0xac, 0x09, 0x2b, 0x22, 0x00,
        0x06, 0xb1, 0x9c, 0xcc, 0xb5, 0x26, 0xb4, 0x30,
        0xeb, 0x76, 0x83, 0xc0, 0xdf, 0x90, 0x3a, 0x88,
        0xf6, 0xf1, 0x09, 0x52, 0xbc, 0xa4, 0xd6, 0x45,
        0x28, 0x4f, 0xf7, 0xed, 0x95, 0xc6, 0xa4, 0xe9,
        0x67, 0xf5, 0xe7, 0xae, 0x22, 0xc9, 0x33, 0xcb,
    ];
    const MG_HASH: [u8; 32] = [
        0x1c, 0x09, 0xf4, 0x62, 0xf1, 0xb5, 0x8f, 0xc1,
        0x40, 0xc9, 0x3c, 0xda, 0x6f, 0xec, 0x88, 0x85,
        0x08, 0x44, 0xe3, 0xf0, 0x04, 0xb7, 0x24, 0x87,
        0xb6, 0x53, 0x39, 0xbd, 0xc0, 0xe4, 0x17, 0x97,
    ];
    const SMALL_MMAX_MOD: u8 = 16;
    const SMALL_MMAX: usize = 1 << SMALL_MMAX_MOD;
    const MG_HASH_SMALL: [u8; 32] = [
        0x8c, 0x55, 0x49, 0x7e, 0x28, 0xd5, 0xea, 0x75,
        0x15, 0xdd, 0x32, 0xb3, 0x98, 0x34, 0x0b, 0xfa,
        0xf8, 0x89, 0x40, 0x35, 0xe0, 0x30, 0xd2, 0x13,
        0x50, 0x80, 0x84, 0x31, 0xb8, 0x00, 0x8a, 0xf2
    ];
    #[test]
    fn create_private_key() {
        PrivateKey::new();
    }
    #[test]
    fn create_public_key() {
        let pubkey = PublicKey::new(&PRIVKEY.into());
        assert_eq!(pubkey, PUBKEY.try_into().unwrap());
    }
/*
// For selector tests.

static const uint64_t index_counts[] = { 1000, 1000, 1000 };
static const uint8_t n_indexes = 3;
static const uint64_t ciphers_count = 3000ULL;
static const uint64_t idx = 12345678;
static const uint64_t rows[] = { idx / 1'000'000ULL, (idx % 1'000'000ULL) / 1'000ULL, (idx % 1'000ULL) };
static const unsigned char selector_hash[] = {
	0xda, 0x20, 0x9d, 0x4f, 0x85, 0xad, 0x0d, 0xb2,
	0x68, 0x45, 0x6f, 0x0d, 0x4e, 0x9e, 0x90, 0x7f,
	0x8f, 0x87, 0x31, 0xa6, 0x69, 0x5d, 0xa5, 0x5f,
	0x1f, 0x3d, 0x19, 0x2f, 0x59, 0xac, 0xe9, 0x0c
};

#define DIMENSION (3)
#define PACKING   (3)
#define ELEM_SIZE (32)
*/

/*
TEST(ECElGamalTest, create_public_key) {
	unsigned char pubkey_test[EPIR_POINT_SIZE];
	epir_pubkey_from_privkey(pubkey_test, privkey);
	ASSERT_PRED2(SamePoint, pubkey_test, pubkey);
}

TEST(ECElGamalTest, encrypt_normal) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt(cipher_test, pubkey, msg, r);
	ASSERT_PRED2(SameCipher, cipher_test, cipher);
}

TEST(ECElGamalTest, encrypt_fast) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt_fast(cipher_test, privkey, msg, r);
	ASSERT_PRED2(SameCipher, cipher_test, cipher);
}

#ifdef TEST_USING_MG
static std::vector<epir_mG_t> mG_test(MG_SMALL_MMAX);

TEST(ECElGamalTest, mG_generate_no_sort) {
	size_t points_computed = 0;
	epir_mG_generate_no_sort(mG_test.data(), mG_test.size(), [](const size_t points_computed_test, void *data) {
		size_t *points_computed = (size_t*)data;
		(*points_computed)++;
		EXPECT_EQ(points_computed_test, *points_computed);
	}, &points_computed);
}

TEST(ECElGamalTest, mG_generate_sort) {
	epir_mG_sort(mG_test.data(), mG_test.size());
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash_small);
}

TEST(ECElGamalTest, mG_generate) {
	epir_mG_generate(mG_test.data(), mG_test.size(), NULL, NULL);
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash_small);
}

TEST(ECElGamalTest, mG_interpolation_search) {
	#pragma omp parallel for
	for(size_t i=0; i<mG_test.size(); i++) {
		epir_mG_t mG = mG_test[i];
		const int32_t scalar_test = epir_mG_interpolation_search(mG.point, mG_test.data(), mG_test.size());
		EXPECT_EQ(scalar_test, (int32_t)mG.scalar);
	}
}

TEST(ECElGamalTest, mG_default_path) {
	char path_default[epir_mG_default_path_length() + 1];
	epir_mG_default_path(path_default, epir_mG_default_path_length() + 1);
	EXPECT_EQ(std::string(path_default), std::string(getenv("HOME")) + "/" + EPIR_DEFAULT_DATA_DIR + "/mG.bin");
}

TEST(ECElGamalTest, mG_load_default) {
	// Write mG.bin to /tmp/mG.bin.
	const std::string path = "/tmp/mG.bin";
	std::ofstream ofs(std::string(path), std::ios::binary | std::ios::out);
	ASSERT_FALSE(ofs.fail());
	ofs.write((const char*)mG_test.data(), sizeof(epir_mG_t) * mG_test.size());
	ofs.close();
	// Load.
	static std::vector<epir_mG_t> mG_test2(mG_test.size());
	const size_t elems_read = epir_mG_load(mG_test2.data(), mG_test.size(), path.c_str());
	EXPECT_EQ(elems_read, mG_test.size());
	EXPECT_PRED2(SameHash<epir_mG_t>, mG_test2, mG_hash_small);
	// Delete.
	EXPECT_TRUE(std::filesystem::remove(path));
}

TEST(ECElGamalTest, decrypt_success) {
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, decrypt_fail) {
	const int32_t decrypted = epir_ecelgamal_decrypt(pubkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, -1);
}

TEST(ECElGamalTest, random_encrypt_normal) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt(cipher_test, pubkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, random_encrypt_fast) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt_fast(cipher_test, privkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}
#endif

int main(int argc, char *argv[]) {
	::testing::InitGoogleTest(&argc, argv);
	const size_t elems_read = epir_mG_load(mG.data(), EPIR_DEFAULT_MG_MAX, NULL);
	EXPECT_EQ(elems_read, (size_t)EPIR_DEFAULT_MG_MAX);
	return RUN_ALL_TESTS();
}
*/
}
