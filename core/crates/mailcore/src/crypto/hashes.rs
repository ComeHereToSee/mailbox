//! Hash selection by OID and CBC helpers shared by the S/MIME and PKCS#12 code.

use cbc::cipher::{BlockCipher, BlockDecryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7};
use der::oid::ObjectIdentifier as Oid;
use sha2::Digest;

pub const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
pub const SHA224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.4");
pub const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// Runs `$body` with `$D` bound to the digest type of `$alg`.
macro_rules! with_hash {
    ($alg:expr, $D:ident => $body:expr) => {
        match $alg {
            $crate::crypto::hashes::HashAlg::Sha1 => {
                type $D = sha1::Sha1;
                $body
            }
            $crate::crypto::hashes::HashAlg::Sha224 => {
                type $D = sha2::Sha224;
                $body
            }
            $crate::crypto::hashes::HashAlg::Sha256 => {
                type $D = sha2::Sha256;
                $body
            }
            $crate::crypto::hashes::HashAlg::Sha384 => {
                type $D = sha2::Sha384;
                $body
            }
            $crate::crypto::hashes::HashAlg::Sha512 => {
                type $D = sha2::Sha512;
                $body
            }
        }
    };
}
pub(crate) use with_hash;

impl HashAlg {
    pub fn from_digest_oid(oid: &Oid) -> Option<HashAlg> {
        Some(match *oid {
            SHA1 => HashAlg::Sha1,
            SHA224 => HashAlg::Sha224,
            SHA256 => HashAlg::Sha256,
            SHA384 => HashAlg::Sha384,
            SHA512 => HashAlg::Sha512,
            _ => return None,
        })
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        with_hash!(self, D => D::digest(data).to_vec())
    }

    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha224 => 28,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// Input block size (the PKCS#12 KDF's `v`).
    pub fn block_len(self) -> usize {
        match self {
            HashAlg::Sha384 | HashAlg::Sha512 => 128,
            _ => 64,
        }
    }
}

/// CBC decryption with PKCS#7 padding; None on a bad key/IV length or padding.
pub fn cbc_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>>
where
    C: BlockCipher + BlockDecryptMut + KeyInit,
{
    cbc::Decryptor::<C>::new_from_slices(key, iv).ok()?.decrypt_padded_vec_mut::<Pkcs7>(data).ok()
}
