use blst::{blst_scalar, min_pk::SecretKey, blst_p1};
mod signature;
mod blindsignature;

fn main() {
    signature::print_hello();

    let msg: &[u8; 11] = b"Hello World";
    let dst: &[u8; 16] = b"Domain-Seperator";

    let sk: SecretKey = signature::gen_sk();
    let pk: blst::min_pk::PublicKey = signature::pk_from_sk(&sk);

    let signature: blst::min_pk::Signature = signature::sign(msg, dst, &sk);

    println!("Regular signature verified: {}", signature::verify(signature, msg, dst, &pk));

    test_blind_sig();
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