use blst::*;
use std::ptr::null;
use rand::RngCore;

/*
    BLS Blind Signatures
*/

pub fn gen_r() -> blst_scalar {
  let mut rng = rand::thread_rng();
  let mut r_seed: [u8; 32] = [1u8; 32];
  rng.fill_bytes(&mut r_seed);

  let mut r: blst_scalar = blst_scalar::default();
  unsafe {
    blst_scalar_from_be_bytes(&mut r, r_seed.as_ptr(), 32);
  }
  return r;
}

pub fn gen_blindsig_sk() -> blst_scalar {
  let mut rng = rand::thread_rng();
  let mut ikm: [u8; 32] = [1u8; 32];
  rng.fill_bytes(&mut ikm);
  let mut sk: blst_scalar = blst_scalar::default();
  unsafe {
    blst_keygen(&mut sk, ikm.as_ptr(), 32, null(), 0);
  }
  return sk;
}

pub fn blindsig_sk_to_pk(sk: &blst_scalar) -> blst_p1 {
  let mut pk: blst_p1 = blst_p1::default();
  unsafe {
    blst_sk_to_pk_in_g1(&mut pk, sk);
  }
  return pk;
}

pub fn hash_msg_to_curve(msg: &str) -> blst_p2 {
  let mut hashed_msg = blst_p2::default();
  //let DST = b"MY-DST"; // if we do this here, we need to pass the same value
  //to verify as well.
  unsafe {
      blst_hash_to_g2(&mut hashed_msg, msg.as_bytes().as_ptr(), msg.len(), null(), 0, null(), 0);
  }
  return hashed_msg;
}

pub fn blind(msg: &str, r: &blst_scalar) ->  blst_p2 {
  let hashed_msg: blst_p2 = hash_msg_to_curve(msg);
  let mut blinded_msg: blst_p2 = blst_p2::default();
  unsafe {
    blst_sign_pk_in_g1(&mut blinded_msg, &hashed_msg, r);
  }
  return blinded_msg;
}

pub fn sign(blinded_message: &blst_p2, sk: &blst_scalar) -> blst_p2 {
  let mut blinded_signature = blst_p2::default();
  // should also check that the point is on the curve!
  unsafe {
    let mut ret: bool = blst_p2_on_curve(blinded_message);
    if ret == false {
      println!("ERROR: Blinded message isn't on curve!");
      return blst_p2::default();
    }

    ret = blst_p2_in_g2(blinded_message);
    if ret == false {
      println!("ERROR: Blinded message isn't in group!");
      return blst_p2::default();
    }

    blst_sign_pk_in_g1(&mut blinded_signature, blinded_message, sk);
  }
  return blinded_signature;
}

pub fn unblind(blinded_signature: &blst_p2, r: &blst_scalar) -> blst_p2 {
  let mut r_inv: blst_scalar = blst_scalar::default();
  let mut signature: blst_p2 = blst_p2::default();
  unsafe {
    blst_sk_inverse(&mut r_inv, r);
    blst_sign_pk_in_g1(&mut signature, blinded_signature, &r_inv);
  }
  return signature;
}

pub fn verify(pk: &blst_p1, sig: &blst_p2, msg: &str ) -> bool {
  unsafe {
    let mut pk_affine: blst_p1_affine = blst_p1_affine::default();
    let mut sig_affine: blst_p2_affine = blst_p2_affine::default();
    blst_p1_to_affine(&mut pk_affine, pk);
    blst_p2_to_affine(&mut sig_affine, sig);
    let ret: BLST_ERROR = blst_core_verify_pk_in_g1(&pk_affine, &sig_affine, true, msg.as_bytes().as_ptr(), msg.len(), null(), 0, [].as_ptr(), 0);

    if ret == BLST_ERROR::BLST_SUCCESS {
      return true;
    } else {
      return false;
    }
  }
}