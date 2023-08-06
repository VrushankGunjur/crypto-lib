use sha2::{Sha256, Sha512, Digest};
use blst::*;

pub fn hash(msg: &[u8]) {
  let mut hasher = Sha256::new();
  hasher.update(msg);
  let _res = hasher.finalize();
}

pub fn hash_to_blst_scalar(hash: &[u8]) -> blst_scalar {
  let mut h_msg = blst_scalar::default();
  unsafe {
      blst_scalar_from_lendian(&mut h_msg, hash.as_ptr());  // perhaps from le_bytes instead
  }
  return h_msg
}