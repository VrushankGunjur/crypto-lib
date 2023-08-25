use blst::{blst_scalar, min_pk::SecretKey, blst_p1};
mod signature;
mod blindsignature;
mod elgamal;
mod additiveeglamal;
mod bjj_ah_elgamal;

fn main() {
    //signature::print_hello();

    let mut pass = 0u8;
    let sig_pass = test_sig();
    println!("Signature test passed: {}", sig_pass);
    pass += sig_pass as u8;

    let blind_pass = test_blind_sig();
    println!("Blind signature test passed: {}", blind_pass);
    pass += blind_pass as u8;

    let elgamal_pass = test_elgamal();
    println!("Elgamal test passing: {}", elgamal_pass);
    pass += elgamal_pass as u8;

    let additive_elgamal_pass = test_additive_elgamal();
    println!("Additive Elgamal test passing: {}", additive_elgamal_pass);
    pass += additive_elgamal_pass as u8;

    let bjj_additive_elgamal_pass = test_bjj_ah_elgamal();
    println!("BJJ Additive Elgamal test passing: {}", bjj_additive_elgamal_pass);
    pass += additive_elgamal_pass as u8;

    println!("Tests passing: {}%", (pass / 4) * 100);
}

fn test_sig() -> bool {
  let msg: &[u8; 11] = b"Hello World";
  let dst: &[u8; 16] = b"Domain-Seperator";

  let sk: SecretKey = signature::gen_sk();
  let pk: blst::min_pk::PublicKey = signature::pk_from_sk(&sk);

  let signature: blst::min_pk::Signature = signature::sign(msg, dst, &sk);

  return signature::verify(signature, msg, dst, &pk);
}
/*
    Should pick r by doing the following:
    r = blst.Scalar().from_bendian(os.urandom(32))  # should be PRF in real life...
*/
fn test_blind_sig() -> bool {
  let msg: &str = "This is a much longer message that I want signed and blinded";

  let r: blst_scalar = blindsignature::gen_r();

  let blinded_message: blst::blst_p2 = blindsignature::blind(msg, &r);

  let sk: blst_scalar = blindsignature::gen_blindsig_sk();
  let pk: blst_p1 = blindsignature::blindsig_sk_to_pk(&sk);

  // let test_signature = blindsignature::sign(&blindsignature::hash_msg_to_curve(msg, msg_len), &sk);

  let blinded_signature: blst::blst_p2 = blindsignature::sign(&blinded_message, &sk);
  let final_signature: blst::blst_p2 = blindsignature::unblind(&blinded_signature, &r);

  let final_verify: bool = blindsignature::verify(&pk, &final_signature, msg);
  
  //println!("Blind signature verification success: {}", final_verify);

  return final_verify;
} 

fn test_elgamal() -> bool {
  let msg = "Another, longer message with special characters !@#$%^&*() that I want to encrypt";

  let sk = elgamal::get_sk();
  let pk = elgamal::sk_to_pk(&sk);
  let nonce = elgamal::gen_nonce();

  let (ciphertext, v )= elgamal::encrypt(msg, pk, &nonce);

  let decrypted_msg = elgamal::decrypt(sk, v, ciphertext, &nonce);

  //println!("{}", decrypted_msg);
  assert_eq!(decrypted_msg, msg);
  //println!("Elgamal Operational: {}", decrypted_msg == msg);
  return decrypted_msg == msg;
}

fn test_additive_elgamal() -> bool {
  let num1: u32 = 2000u32;
  let num2: u32 = 3000u32;

  // encrypt to this pair
  let sk = additiveeglamal::get_sk();
  let pk = additiveeglamal::sk_to_pk(&sk);

  let c1 = additiveeglamal::encrypt(&num1, pk);

  let c2 = additiveeglamal::encrypt(&num2, pk);

  let c_combined = additiveeglamal::add_encryptions(&vec![c1, c2]);

  let rerandomized_c = additiveeglamal::rerandomize(pk, c_combined);
  assert!(rerandomized_c.0.x != c_combined.0.x);

  let decrypted_msg: u32 = additiveeglamal::decrypt(sk, rerandomized_c);
  println!("{}", decrypted_msg);
  return decrypted_msg == num1 + num2;
}

fn test_bjj_ah_elgamal() -> bool {
  let num1 = 1u32;
  let num2 = 2u32;

  let sk = bjj_ah_elgamal::get_sk();
  let pk = bjj_ah_elgamal::sk_to_pk(&sk);

  let c1 = bjj_ah_elgamal::encrypt(&num1, &pk);

  let c2 = bjj_ah_elgamal::encrypt(&num2, &pk);

  let c = bjj_ah_elgamal::add_encryptions(&vec![c1, c2]);
  let rerand_c = bjj_ah_elgamal::rerandomize(&pk, c);
  let decrypt = bjj_ah_elgamal::decrypt(&sk, rerand_c);

  println!("{}", decrypt);
  return decrypt == num1 + num2;
}