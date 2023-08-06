use blst::{blst_scalar, min_pk::SecretKey, blst_p1};
mod signature;
mod blindsignature;
mod elgamal;

fn main() {
    signature::print_hello();

    
    let msg: &[u8; 11] = b"Hello World";
    let dst: &[u8; 16] = b"Domain-Seperator";

    let sk: SecretKey = signature::gen_sk();
    let pk: blst::min_pk::PublicKey = signature::pk_from_sk(&sk);

    let signature: blst::min_pk::Signature = signature::sign(msg, dst, &sk);

    println!("Regular signature verified: {}", signature::verify(signature, msg, dst, &pk));

    test_blind_sig();
    test_elgamal();
}

/*
    Should pick r by doing the following:
    r = blst.Scalar().from_bendian(os.urandom(32))  # should be PRF in real life...
*/
fn test_blind_sig() {
  let msg: &str = "This is a much longer message that I want signed and blinded";

  let r: blst_scalar = blindsignature::gen_r();

  let blinded_message: blst::blst_p2 = blindsignature::blind(msg, &r);

  let sk: blst_scalar = blindsignature::gen_blindsig_sk();
  let pk: blst_p1 = blindsignature::blindsig_sk_to_pk(&sk);

  // let test_signature = blindsignature::sign(&blindsignature::hash_msg_to_curve(msg, msg_len), &sk);

  let blinded_signature: blst::blst_p2 = blindsignature::sign(&blinded_message, &sk);
  let final_signature: blst::blst_p2 = blindsignature::unblind(&blinded_signature, &r);

  let final_verify: bool = blindsignature::verify(&pk, &final_signature, msg);
  
  println!("Blind signature verification success: {}", final_verify);
} 

fn test_elgamal() {
  let msg = "Another, longer message with special characters !@#$%^&*() that I want to encrypt";

  let sk = elgamal::get_sk();
  let pk = elgamal::sk_to_pk(&sk);
  let nonce = [0; 12];
  let encrypt_ret = elgamal::encrypt(msg, pk, &nonce);

  let ciphertext = encrypt_ret.0;
  let v = encrypt_ret.1;

  let decrypt_msg = elgamal::decrypt(sk, v, ciphertext, &nonce);
  println!("{}", decrypt_msg);
  assert_eq!(decrypt_msg, msg);
  println!("Elgamal Operational: {}", decrypt_msg == msg);
}