use libsecp256k1::{*, curve::*};
use sha2::{Sha256, Digest};
use aes_gcm::{
  aead::{Aead, KeyInit, generic_array::GenericArray},
  Aes256Gcm, Key // Or `Aes128Gcm`
};

pub fn mult_test () {
  let gen_ctx = &ECMULT_GEN_CONTEXT;
  let mul_ctx = &ECMULT_CONTEXT;

  let mut g_a = Jacobian::default();
  let alpha = Scalar::from_int(3);
  gen_ctx.ecmult_gen(&mut g_a, &alpha); // g * a

  let mut g_b = Jacobian::default();
  let beta = Scalar::from_int(2);
  gen_ctx.ecmult_gen(&mut g_b, &beta);  // g * b ( this is jacobian * scalar! )

  let mut g_a_b = Jacobian::default();
  mul_ctx.ecmult_const(&mut g_a_b, &Affine::from_gej(&g_a), &beta); // this is affine * scalar!

  let mut g_b_a = Jacobian::default();
  mul_ctx.ecmult_const(&mut g_b_a, &Affine::from_gej(&g_b), &alpha);

  let test = Affine::from_gej(&g_b_a);
  let test2 = Affine::from_gej(&g_a_b);
  println!("Test Concluded");
}

pub fn get_sk () -> Scalar {
  // let mut sk = Scalar::default();
  // let mut rng = rand::thread_rng();
  // let mut seed: [u8; 32] = [1u8; 32];
  // rng.fill_bytes(&mut seed);
  // let ret = sk.set_b32(&seed);
  return Scalar::from_int(rand::random());
}

pub fn sk_to_pk (sk: &Scalar) -> Jacobian {
  let context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;

  let mut pk: Jacobian = Jacobian::default();

  context.ecmult_gen(&mut pk, sk);
  return pk;
}

pub fn encrypt(msg: &str, pk: Jacobian, nonce: &[u8; 12]) -> (Vec<u8>, Jacobian) {
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let sk2: Scalar = Scalar::from_int(rand::random());

  let mut v: Jacobian = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut v, &sk2); // g * sk2 = v

  let mut w: Jacobian = Jacobian::default();
  mul_context.ecmult_const(&mut w, &Affine::from_gej(&pk), &sk2); // pk * sk2 = g * sk * sk2 = w

  let key: [u8; 32] = hash_v_w_to_key(v, w);

  let key = Key::<Aes256Gcm>::from_slice(&key);
  let cipher = Aes256Gcm::new(&key);
  let res = cipher.encrypt(GenericArray::from_slice(nonce), msg.as_bytes().as_ref());

  let ciphertext: Vec<u8> = res.unwrap();

  return (ciphertext, v);
}

fn hash_v_w_to_key(v: Jacobian, w: Jacobian) -> [u8; 32] {
  let mut v_affine: Affine = Affine::from_gej(&v);
  let mut w_affine: Affine = Affine::from_gej(&w);
  v_affine.x.normalize();
  v_affine.y.normalize();
  w_affine.x.normalize();
  w_affine.y.normalize();
  let hash_input: Vec<u8> = [v_affine.x.b32(), v_affine.y.b32(), w_affine.x.b32(), w_affine.y.b32()].concat();

  let mut hasher = Sha256::new();
  hasher.update(hash_input);
  let key: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
  return key;
}

pub fn decrypt(sk: Scalar, v: Jacobian, ciphertext: Vec<u8>, nonce: &[u8; 12]) -> String {

  let context: &ECMultContext = &ECMULT_CONTEXT;
  let mut w: Jacobian = Jacobian::default();
  context.ecmult_const(&mut w, &Affine::from_gej(&v), &sk); // g * sk2 * sk = w
  
  let key: [u8; 32] = hash_v_w_to_key(v, w);
  let key = Key::<Aes256Gcm>::from_slice(&key);
  let cipher = Aes256Gcm::new(&key);
  let res = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref());

  let msg_bytes: Vec<u8> = res.unwrap();
  return String::from_utf8(msg_bytes).unwrap();
}