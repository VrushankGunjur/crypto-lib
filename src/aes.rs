use aes_gcm::{
  aead::{Aead, AeadCore, KeyInit, OsRng, generic_array::GenericArray},
  Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

pub fn encrypt(msg: &str, key: [u8; 32], nonce: &[u8; 12]) -> (Vec<u8>, Jacobian) {
  let key = Key::<Aes256Gcm>::from_slice(&key);
  let cipher = Aes256Gcm::new(&key);
  let res = cipher.encrypt(GenericArray::from_slice(nonce), msg.as_bytes().as_ref());

  let ciphertext: Vec<u8> = res.unwrap();

  return (ciphertext, v);
}

pub fn decrypt(ciphertext: Vec<u8>, key: [u8; 32], nonce: &[u8; 12]) {

  let key = Key::<Aes256Gcm>::from_slice(&key);
  let cipher = Aes256Gcm::new(&key);
  let res = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref());

  let msg_bytes = res.unwrap();
  return String::from_utf8(msg_bytes).unwrap();
}