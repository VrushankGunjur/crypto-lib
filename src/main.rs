use blst::{blst_scalar, min_pk::SecretKey, blst_p1};
mod signature;
mod blindsignature;
mod elgamal;
mod additiveeglamal;
mod bjj_ah_elgamal;
mod hash;
mod merklehelper;
use ff::PrimeField;
//use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use poseidon_rs::Fr;

use rand::Rng;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};


use std::fs::{File, OpenOptions};
use std::io::{self, Write};

use crate::{bjj_ah_elgamal::print_point, blindsignature::gen_r};
//use ff::{PrimeField, Field};

fn main() {
    //signature::print_hello();

    // let ret = merklehelper::gen_proof_naive(&leaves, 4, 1).unwrap();

    // println!("Root: {}", ret.0.to_string());
    // let mut hp = ret.1;
    // for (i, e) in hp.iter().enumerate() {
    //     println!("{}: {}", i, e.to_string());
    // }

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

    let merkleization_pass = test_merkleization();
    println!("Merkleization test passing: {}", merkleization_pass);
    pass += merkleization_pass as u8;
    println!("Tests passing: {}%", (pass as f32 / 6_f32) * 100_f32);


    //gen_encrypt();

    //gen_r_del_cli();
    //gen_r_del_solidity();
    gen_r_del_master().unwrap();
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

  assert_eq!(decrypted_msg, msg);
  return decrypted_msg == msg;
}

/*
    This version of additive elgamal doesn't currently support fast discrete log, or enc(0) and encryption subtraction.
*/
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
  let num1 = 1_000_000u32;
  let num2 = 2_500_000u32;
  let num3 = 0u32;
  let num4 = 1u32;
//   let num1 = 10_000;
//   let num2 = 20_000;

  let sk = bjj_ah_elgamal::get_sk();
  let pk = bjj_ah_elgamal::sk_to_pk(&sk);

  let c1 = bjj_ah_elgamal::encrypt(&num1, &pk, &bjj_ah_elgamal::gen_rand_bigint());

  let c2 = bjj_ah_elgamal::encrypt(&num2, &pk, &bjj_ah_elgamal::gen_rand_bigint());

  let c3 = bjj_ah_elgamal::encrypt(&num3, &pk, &bjj_ah_elgamal::gen_rand_bigint());

  let c4 = bjj_ah_elgamal::encrypt(&num4, &pk, &bjj_ah_elgamal::gen_rand_bigint());
  let mut c = bjj_ah_elgamal::add_encryptions(&vec![c1, c2, c3]);

  c = bjj_ah_elgamal::subtract_encryptions(c, c4);
  let rerand_c = bjj_ah_elgamal::rerandomize(&pk, &c);

  assert!(rerand_c.0.x != c.0.x);

  let decrypt = bjj_ah_elgamal::decrypt(&sk, rerand_c);

  println!("{}", decrypt);
  return decrypt == num1 + num2 + num3 - num4;
}

fn test_merkleization() -> bool {
    let leaves = vec![Fr::from_str("1").unwrap(), Fr::from_str("2").unwrap()];
    let ss_ret = merklehelper::gen_proof_padded(&leaves, 4, 1).unwrap();
    println!("SRoot: {}", ss_ret.0.to_string());
    // let hp = ss_ret.1;
    // for (i, e) in hp.iter().enumerate() {
    //     println!("{}: {}", i, e.to_string());
    // }

    return ss_ret.0.to_string() == "Fr(0x0ee44ff6038010b81e2e310efd8abfeb658b8f8f5e415bc90ac4426683f9c958)";
}

fn gen_encrypt() {
    let mut rng = rand::thread_rng();

    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);
    bjj_ah_elgamal::print_point(&pk, "pk_enc");

    let randomness = rng.gen_range(1..10).to_bigint().unwrap();
    println!("Random: {}", randomness.to_string());
    let ret = bjj_ah_elgamal::encrypt(&50000, &pk, &randomness);
    bjj_ah_elgamal::print_point(&ret.0.affine(), "e");
    bjj_ah_elgamal::print_point(&ret.1.affine(), "v");
}


fn gen_r_del_master() -> io::Result<()> {
    let solidity_path = "inputs.txt";
    let iiopts = OpenOptions::new().create(true).append(true).open(solidity_path)?;
    let mut inputsarray = io::BufWriter::new(iiopts);

    let prover_path = "Prover.txt";
    let piopts = OpenOptions::new().create(true).append(true).open(prover_path)?;
    let mut proverinfo = io::BufWriter::new(piopts);

    let mut rng = rand::thread_rng();

    let tv = 300;

    //println!("[WIT] T_v: {}", tv);

    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);

    let mut input_ctr: u32 = 0;

    writeln!(inputsarray, "// pk:")?;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_x_str(&pk))?;
    input_ctr += 1;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_y_str(&pk))?;
    input_ctr += 1;

    //bjj_ah_elgamal::print_point(&pk, "pk_enc");

    let mut addrs = Vec::new();
    let anonymity_set_size = 10;

    //println!("addrs:");
    for i in 1..(anonymity_set_size+1) {
        //println!("Addr{}, {}", i, i);
        addrs.push(i);
    }

    let target_del_idx = rng.gen_range(0..anonymity_set_size);
    //println!("Target delegate index: {}, with addr {}", target_del_idx, addrs[target_del_idx]);

    let mut cts = Vec::new();
    let mut random_states = Vec::new();
    for i in 0..anonymity_set_size {
        random_states.push(rng.gen_range(1..10).to_bigint().unwrap());
        if i == target_del_idx {
            // encryption of tv
            cts.push(bjj_ah_elgamal::encrypt(&tv, &pk, &random_states[i]));
        } else {
            // encryption of 0
            cts.push(bjj_ah_elgamal::encrypt(&0, &pk, &random_states[i]));
        }
    }

    let mut prover_ct_str = "[".to_owned();

    writeln!(inputsarray, "// cts:")?;
    for (_, ct )in cts.iter().enumerate() {
        // e_x and e_y
        let e_x =  bjj_ah_elgamal::point_x_str(&ct.0.affine());
        let e_y =  bjj_ah_elgamal::point_y_str(&ct.0.affine());
        let v_x =  bjj_ah_elgamal::point_x_str(&ct.1.affine());
        let v_y =  bjj_ah_elgamal::point_y_str(&ct.1.affine());

        prover_ct_str.push_str(&("\"".to_owned() + &e_x + "\", "));
        prover_ct_str.push_str(&("\"".to_owned() + &e_y + "\", "));
        prover_ct_str.push_str(&("\"".to_owned() + &v_x + "\", "));
        prover_ct_str.push_str(&("\"".to_owned() + &v_y + "\", "));

        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, e_x)?;
        input_ctr += 1;
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, e_y)?;
        input_ctr += 1;

        // v_x and v_y
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, v_x)?;
        input_ctr += 1;
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, v_y)?;
        input_ctr += 1;

    }

    let mut prover_randoms_str = "[".to_owned();
    writeln!(inputsarray, "// ct_random_states:")?;
    for (i, r )in random_states.iter().enumerate() {
        prover_randoms_str.push_str(&("\"".to_owned() + &r.to_str_radix(16) + "\", "));

        let r_string = r.to_str_radix(16);
        let padding = "0x".to_string() + &String::from_utf8(vec![b'0'; 64-r_string.len()]).unwrap();
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, padding + &r_string)?;
        input_ctr += 1;
        //println!("r_{}: {}", i, r.to_string());
    }

    let mut prover_delegate_addr_str = "[".to_owned();

    writeln!(inputsarray, "// delegates (addrs):")?;
    for (_, a) in addrs.iter().enumerate() {
        prover_delegate_addr_str.push_str(&("\"".to_owned() + &a.to_string() + "\", "));

        let a_string = format!("{:x}", a);
        let padding = "0x".to_string() + &String::from_utf8(vec![b'0'; 64-a_string.len()]).unwrap();
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, padding + &a_string)?;
        input_ctr += 1;
    }

    // merkle proof for T_v
    let (root, hashpath) = merklehelper::gen_proof_padded(
        &vec![Fr::from_str("0").unwrap(),
        Fr::from_str("1").unwrap(),
        Fr::from_str(&tv.to_string()).unwrap(),
        Fr::from_str("2").unwrap()],
        20, 2).unwrap();
    
    writeln!(inputsarray, "// Vote Root:")?;
    let root_string = root.to_string();
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, &root_string[3..root_string.len()-1])?;
    input_ctr += 1;

    writeln!(inputsarray, "// Vote Hashpath:")?;
    for elem in hashpath.iter() {
        let s = elem.to_string();
        let len = s.len();
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, &s[3..len-1])?;
        input_ctr += 1;
    }

    writeln!(inputsarray, "// Vote Index:")?;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, "0x0000000000000000000000000000000000000000000000000000000000000002")?;


    // write to Prover
    prover_randoms_str = prover_randoms_str[0..prover_randoms_str.len()-2].to_string();
    prover_randoms_str.push_str("]");
    writeln!(proverinfo, "ct_random_states = {}", prover_randoms_str)?;

    prover_ct_str = prover_ct_str[0..prover_ct_str.len()-2].to_string();
    prover_ct_str.push_str("]");
    writeln!(proverinfo, "cts = {}", prover_ct_str)?;

    writeln!(proverinfo, "delegate_addr = \"{}\"", addrs[target_del_idx])?;

    prover_delegate_addr_str = prover_delegate_addr_str[0..prover_delegate_addr_str.len()-2].to_string();
    prover_delegate_addr_str.push_str("]");
    writeln!(proverinfo, "delegates = {}", prover_delegate_addr_str)?;

    writeln!(proverinfo, "pk_enc_x = \"{}\"", bjj_ah_elgamal::point_x_str(&pk))?;
    writeln!(proverinfo, "pk_enc_y = \"{}\"", bjj_ah_elgamal::point_y_str(&pk))?;

    writeln!(proverinfo, "t_v = \"{}\"", tv)?;

    // create string out of hashpath
    let mut prover_hp_string = "[".to_owned();
    for m in hashpath.iter() {
        let mut cur = m.to_string();
        cur = cur[3..cur.len()-1].to_string();
        prover_hp_string.push_str(&("\"".to_owned() + &cur + "\", "))
    }
    prover_hp_string = prover_hp_string[0..prover_hp_string.len()-2].to_string();
    prover_hp_string.push_str("]");

    writeln!(proverinfo, "vote_hashpath = {}", prover_hp_string)?;


    writeln!(proverinfo, "vote_idx = \"2\"")?;
    writeln!(proverinfo, "vote_root = \"{}\"", &root_string[3..root_string.len()-1])?;
    Ok(())
}