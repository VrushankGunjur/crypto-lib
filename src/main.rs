use babyjubjub_rs::Point;
use blst::{blst_scalar, min_pk::SecretKey as blstSecretKey, blst_p1};
mod signature;
mod blindsignature;
mod elgamal;
mod additiveeglamal;
mod bjj_ah_elgamal;
//mod hash;
mod merklehelper;
use ecdsa::signature::Signer;
use ff::PrimeField;
use ff::hex::ToHex;
//use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use poseidon_rs::{Fr, Poseidon};

use rand::Rng;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use rand::rngs::OsRng;

use std::any::Any;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::str::FromStr;

//use ff::{PrimeField, Field};
use noir_rs::{
    native_types::{Witness, WitnessMap},
    FieldElement,
};
use serde_json::Value;
use std::fs;

use k256::ecdsa::{hazmat::SignPrimitive, RecoveryId, VerifyingKey, Signature, SigningKey};
use sha3::{Keccak256, Digest};
use hex_literal::hex;

use ethers_core::rand::thread_rng;
// use ethers_signers::{LocalWallet, Signer};

fn main() {
    //signature::print_hello();

    // let ret = merklehelper::gen_proof_naive(&leaves, 4, 1).unwrap();

    // println!("Root: {}", ret.0.to_string());
    // let mut hp = ret.1;
    // for (i, e) in hp.iter().enumerate() {
    //     println!("{}: {}", i, e.to_string());
    // }

    const RUN_TEST: bool = false;

    if RUN_TEST {
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
    }

    //gen_ecdsa();
    //test_r_dec_prove_verify()
    //gen_encrypt();
    //test_r_dec_prove_verify();

    // sp_mult();
    //gen_r_sub();
    //gen_r_encsub();
    gen_r_vecadd();
    //gen_r_del_master().unwrap();
    //gaen_r_vote_master().unwrap();
    //gen_r_dec_master();
}

//  fn gen_ecdsa() {
//     // let signing_key = SigningKey::from_bytes(&hex!(
//     //     "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
//     // ).into()).unwrap();
    
//     // let msg = hex!("e9808504e3b29200831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080018080");
//     // let digest = Keccak256::new_with_prefix(msg);
//     // let (signature, recid) = signing_key.sign_digest_recoverable(digest).unwrap();
    
//     // assert_eq!(
//     //     signature.to_bytes().as_slice(),
//     //     &hex!("c9cf86333bcb065d140032ecaab5d9281bde80f21b9687b3e94161de42d51895727a108a0b8d101465414033c3f705a9c7b826e596766046ee1183dbc8aeaa68")
//     // );
    
//     // assert_eq!(recid, RecoveryId::try_from(0u8).unwrap());
//     let wallet = LocalWallet::new(&mut thread_rng());

//     // The wallet can be used to sign messages
//     let message = b"hello";
//     let signature = wallet.sign_message(message).await?;

//     assert_eq!(signature.recover(&message[..]).unwrap(), wallet.address());
// }
// fn gen_ecdsa() {
//     // Generate a random private key
//     let private_key = SigningKey::random(&mut OsRng);

//     // Get the corresponding public key
//     let public_key = VerifyingKey::from(&private_key);

//     // Data to be signed
//     let data = b"Hello, world!";

//     // Sign the data
//     let signature: Signature = private_key.sign(data);

//     // Convert the signature components to bytes
//     let r = signature.r();
//     let s = signature.s();
//     let v = signature.type_id();
//     println!("r: {:?}",  r.to_bytes());
//     println!("s: {:?}",  s.to_bytes());
//     // let (r, s) = signature.to_asn1();

//     // Convert public key to bytes (compressed format)
//     //let public_key_bytes = public_key.to_bytes_compressed();
// }

fn sp_mult() {
    let s: u32 = 5000;
    println!("scalar: {}", s);
    let r = bjj_ah_elgamal::get_point(&s);  // g * s
    bjj_ah_elgamal::print_point(&r, "point");

    bjj_ah_elgamal::verbose_multiply(r, BigInt::from_bytes_be(Sign::Plus, &s.to_be_bytes()));   // g * s * s
    

    //bjj_ah_elgamal::verbose_multiply(ret.0.affine(), BigInt::from_bytes_be(Sign::Plus, &11_u32.to_be_bytes()));
    // bjj_ah_elgamal::print_point(&ret.0.affine(), "e");
    // bjj_ah_elgamal::print_point(&ret.1.affine(), "v");
}

fn gen_r_vecadd() {
    let prover_path = "vecadd_Prover.txt";
    let piopts = OpenOptions::new().create(true).append(true).open(prover_path).unwrap();
    let mut proverinfo = io::BufWriter::new(piopts); 

    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);

    let mut summand1_string = "[".to_string();
    let mut summand2_string = "[".to_string();
    let mut sum_string = "[".to_string();
    // generate two ciphertext vectors
    for m in 1..21 {
        let (c1_e_s1, v1_v_s1) = bjj_ah_elgamal::encrypt(&(m as u32), &pk, &BigInt::from_str("2").unwrap());
        
        let s1ex = bjj_ah_elgamal::point_x_str(&c1_e_s1.affine());
        let s1ey = bjj_ah_elgamal::point_y_str(&c1_e_s1.affine());
        let s1vx = bjj_ah_elgamal::point_x_str(&v1_v_s1.affine());
        let s1vy = bjj_ah_elgamal::point_y_str(&v1_v_s1.affine());

        summand1_string.push_str(&("\"".to_owned() + &s1ex + "\", "));
        summand1_string.push_str(&("\"".to_owned() + &s1ey + "\", "));
        summand1_string.push_str(&("\"".to_owned() + &s1vx + "\", "));
        summand1_string.push_str(&("\"".to_owned() + &s1vy + "\", "));

        let (c1_e_s2, v1_v_s2) = bjj_ah_elgamal::encrypt(&(m + 40 as u32), &pk, &BigInt::from_str("4").unwrap());

        let s2ex = bjj_ah_elgamal::point_x_str(&c1_e_s2.affine());
        let s2ey = bjj_ah_elgamal::point_y_str(&c1_e_s2.affine());
        let s2vx = bjj_ah_elgamal::point_x_str(&v1_v_s2.affine());
        let s2vy = bjj_ah_elgamal::point_y_str(&v1_v_s2.affine());

        summand2_string.push_str(&("\"".to_owned() + &s2ex + "\", "));
        summand2_string.push_str(&("\"".to_owned() + &s2ey + "\", "));
        summand2_string.push_str(&("\"".to_owned() + &s2vx + "\", "));
        summand2_string.push_str(&("\"".to_owned() + &s2vy + "\", "));

        let (res_e, res_v) = bjj_ah_elgamal::add_encryptions(&vec![(c1_e_s1.clone(), v1_v_s1.clone()), (c1_e_s2.clone(), v1_v_s2.clone())]);

        let resex = bjj_ah_elgamal::point_x_str(&res_e.affine());
        let resey = bjj_ah_elgamal::point_y_str(&res_e.affine());
        let resvx = bjj_ah_elgamal::point_x_str(&res_v.affine());
        let resvy = bjj_ah_elgamal::point_y_str(&res_v.affine());
        sum_string.push_str(&("\"".to_owned() + &resex + "\", "));
        sum_string.push_str(&("\"".to_owned() + &resey + "\", "));
        sum_string.push_str(&("\"".to_owned() + &resvx + "\", "));
        sum_string.push_str(&("\"".to_owned() + &resvy + "\", "));
    }

    sum_string = sum_string[0..sum_string.len()-2].to_string();
    summand2_string = summand2_string[0..summand2_string.len()-2].to_string();
    summand1_string = summand1_string[0..summand1_string.len()-2].to_string();
    sum_string.push_str("]");
    summand2_string.push_str("]");
    summand1_string.push_str("]");

    writeln!(proverinfo, "summand1 = {}", summand1_string).unwrap();
    writeln!(proverinfo, "summand2 = {}", summand2_string).unwrap();
    writeln!(proverinfo, "sum = {}", sum_string).unwrap();
}

fn gen_r_sub() {
    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);

    let m1: u32 = 2000;
    let m2: u32 = 24;

    let (c1_e, c1_v) = bjj_ah_elgamal::encrypt(&m1, &pk, &BigInt::from_str("2").unwrap()).clone();
    let (c2_e, c2_v) = bjj_ah_elgamal::encrypt(&m2, &pk, &BigInt::from_str("3").unwrap()).clone();

    //let (res_e, res_v) = bjj_ah_elgamal::add_encryptions(&vec![(c1_e.clone(), c1_v.clone()), (c2_e.clone(), c2_v.clone())]);

    bjj_ah_elgamal::print_point(&c1_e.affine(), "c1.e");
    bjj_ah_elgamal::print_point(&c1_v.affine(), "c1.v");

    bjj_ah_elgamal::print_point(&c2_e.clone().affine(), "c2.e");
    bjj_ah_elgamal::print_point(&c2_v.affine(), "c2.v");

    // uncomment to subtract instead of add
    //let (res_e, res_v) = bjj_ah_elgamal::subtract_encryptions((c1_e.clone(), c1_v.clone()), (c2_e.clone(), c2_v.clone()));
    let (res_e, res_v) = bjj_ah_elgamal::add_encryptions(&vec![(c1_e.clone(), c1_v.clone()), (c2_e.clone(), c2_v.clone())]);

    bjj_ah_elgamal::print_point(&res_e.affine(), "res.e");
    bjj_ah_elgamal::print_point(&res_v.affine(), "res.v");

    println!("{}", bjj_ah_elgamal::decrypt(&sk, (res_e, res_v)));
}

fn gen_r_encsub() {
    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);

    bjj_ah_elgamal::print_point(&pk, "pk");
    let m1: u32 = 2000;
    let m2: u32 = 24;

    let (c1_e, c1_v) = bjj_ah_elgamal::encrypt(&m1, &pk, &BigInt::from_str("2").unwrap()).clone();
    //let (c2_e, c2_v) = bjj_ah_elgamal::encrypt(&m2, &pk, &BigInt::from_str("3").unwrap()).clone();

    //let (res_e, res_v) = bjj_ah_elgamal::add_encryptions(&vec![(c1_e.clone(), c1_v.clone()), (c2_e.clone(), c2_v.clone())]);

    bjj_ah_elgamal::print_point(&c1_e.affine(), "c1.e");
    bjj_ah_elgamal::print_point(&c1_v.affine(), "c1.v");

    println!("tpi: {}", m2);

    let (c2_e, c2_v) = bjj_ah_elgamal::encrypt(&m2, &pk, &BigInt::from_str("0").unwrap()).clone();


    let (res_e, res_v) = bjj_ah_elgamal::subtract_encryptions((c1_e.clone(), c1_v.clone()), (c2_e.clone(), c2_v.clone()));

    bjj_ah_elgamal::print_point(&res_e.affine(), "res.e");
    bjj_ah_elgamal::print_point(&res_v.affine(), "res.v");

    println!("{}", bjj_ah_elgamal::decrypt(&sk, (res_e, res_v)));
}

fn test_r_dec_prove_verify() {
    let data =fs::read_to_string("./R_dec.json").expect("Unable to read file");
    let json: Value = serde_json::from_str(&data).expect("Unable to parse JSON");
    let bytecode: &str = json["bytecode"].as_str().expect("Unable to extract bytecode");

    println!("Initializing witness...");
    let mut initial_witness = WitnessMap::new();
    // initial_witness.insert(Witness(1), FieldElement::from(47_i128));
    // initial_witness.insert(Witness(2), FieldElement::from(2_i128));

    // sk
    //initial_witness.insert(Witness(1), FieldElement::from_hex("0x00000000000000000000000000000000000000000000000000000000000046B3").unwrap());
    initial_witness.insert(Witness(1), FieldElement::from(18099_u128));
    //FieldElement::zero();
    // cts
    initial_witness.insert(Witness(2), FieldElement::from_hex("0x00ee1ef97f8a061cb6cf8b664f267888e644d5f2f8b3ea33acce4dda65d3c5c6").unwrap());
    initial_witness.insert(Witness(3), FieldElement::from_hex("0x150b67cc89afadb58f877a1353eda2f52838cde52455daaaaf4e54441afdcd24").unwrap()); 
    initial_witness.insert(Witness(4), FieldElement::from_hex("0x172dba8d231345b865223308fe44ba307c159de512787257113e2a7137f831b4").unwrap()); 
    initial_witness.insert(Witness(5), FieldElement::from_hex("0x25316c6b88a089801a57e442545e52c559cba980f84f44a8fca45c0f821c5cd7").unwrap()); 
    initial_witness.insert(Witness(6), FieldElement::from_hex("0x0f9f02a7711587226f5b124c6f6df35b9acdd3fb5c59fbef8769f4bf6f99c6ec").unwrap()); 
    initial_witness.insert(Witness(7), FieldElement::from_hex("0x0f7d4b13668486bcbbf5de4c42bbb33738b891e824b6deab3f4055c94c340a59").unwrap()); 
    initial_witness.insert(Witness(8), FieldElement::from_hex("0x10c347ae3592776a678f9fc29ecd029f8297367209a4f28f7cb49b09bffd4145").unwrap()); 
    initial_witness.insert(Witness(9), FieldElement::from_hex("0x113f8246f336e8d375c9daab552816825f481c210226f307bc863e017642566c").unwrap()); 
    initial_witness.insert(Witness(10), FieldElement::from_hex("0x0d71deba24a8bb87ba9a7d01be8668595b607b96a49a4fae5f9c955ba651bd53").unwrap()); 
    initial_witness.insert(Witness(11), FieldElement::from_hex("0x1ae06a2f8af0069ebf78d1d0a437c7e2195972fb803202db511ce65b40b807d6").unwrap()); 
    initial_witness.insert(Witness(12), FieldElement::from_hex("0x2c6bfc7fe056ed38e26ec136ec8aec5f63ecc4b52c44afba967649cf1e6e2311").unwrap()); 
    initial_witness.insert(Witness(13), FieldElement::from_hex("0x1ac7675df6265f6e12d1c79a2b3b6658a0d46a320fba497ad0b817f9b19e0f21").unwrap()); 

    let p = FieldElement::from_hex("0x00ee1ef97f8a061cb6cf8b664f267888e644d5f2f8b3ea33acce4dda65d3c5c6").unwrap();
    
    // msg
    //initial_witness.insert(Witness(14), FieldElement::from_hex("0x0000000000000000000000000000000000000000000000000000000000000032").unwrap()); 
    //initial_witness.insert(Witness(15), FieldElement::from_hex("0x0000000000000000000000000000000000000000000000000000000000000014").unwrap()); 
    //initial_witness.insert(Witness(16), FieldElement::from_hex("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap()); 
    initial_witness.insert(Witness(14), FieldElement::from(50_u128));
    initial_witness.insert(Witness(15), FieldElement::from(20_u128));
    initial_witness.insert(Witness(16), FieldElement::from(3_u128));


    println!("Generating proof...");
    let (proof, vk) = noir_rs::prove(String::from(bytecode), initial_witness).unwrap();
    let t: String = String::from_utf8_lossy(&proof.clone()).to_string();
    println!("Verifying proof...");
    let verdict = noir_rs::verify(String::from(bytecode), proof, vk).unwrap();
    assert!(verdict);
    println!("Proof correct");
}


fn test_sig() -> bool {
  let msg: &[u8; 11] = b"Hello World";
  let dst: &[u8; 16] = b"Domain-Seperator";

  let sk: blstSecretKey = signature::gen_sk();
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
  let rerand_c = bjj_ah_elgamal::rerandomize(&pk, &c, &bjj_ah_elgamal::gen_rand_bigint());

  assert!(rerand_c.0.x != c.0.x);

  let decrypt = bjj_ah_elgamal::decrypt(&sk, rerand_c);

  println!("{}", decrypt);
  return decrypt == num1 + num2 + num3 - num4;
}

fn test_merkleization() -> bool {
    let leaves = vec![vec![Fr::from_str("1").unwrap()], vec![Fr::from_str("2").unwrap()]];
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

    //bjj_ah_elgamal::verbose_multiply(ret.0.affine(), BigInt::from_bytes_be(Sign::Plus, &11_u32.to_be_bytes()));
    bjj_ah_elgamal::print_point(&ret.0.affine(), "e");
    bjj_ah_elgamal::print_point(&ret.1.affine(), "v");
}

fn gen_r_dec_master() -> io::Result<()> {
    let prover_path = "dec_Prover.txt";
    let piopts = OpenOptions::new().create(true).append(true).open(prover_path)?;
    let mut proverinfo = io::BufWriter::new(piopts); 

    let mut rng = rand::thread_rng();
    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);



    // Y/N/A
    let tally = vec![50_u32, 20_u32, 3_u32];

    let mut cts = Vec::new();
    let mut ct_string = "[".to_string();
    // encrypt the tally to create cts
    for v in tally.iter() {
        let randomness = rng.gen_range(1..10).to_bigint().unwrap();
        let ct = bjj_ah_elgamal::encrypt(v, &pk, &randomness);

        let e_x =  bjj_ah_elgamal::point_x_str(&ct.0.affine());
        let e_y =  bjj_ah_elgamal::point_y_str(&ct.0.affine());
        let v_x =  bjj_ah_elgamal::point_x_str(&ct.1.affine());
        let v_y =  bjj_ah_elgamal::point_y_str(&ct.1.affine());

        //let p: &mut [u8] = BigInt::from_str(&ct.0.x.to_string()[2..ct.0.x.to_string().len()]).unwrap().to_bytes_be().1.as_mut_slice();
        ct_string.push_str(&("\"".to_owned() + &e_x + "\", "));
        ct_string.push_str(&("\"".to_owned() + &e_y + "\", "));
        ct_string.push_str(&("\"".to_owned() + &v_x + "\", "));
        ct_string.push_str(&("\"".to_owned() + &v_y + "\", "));

        cts.push(ct);
    }

    ct_string = ct_string[0..ct_string.len()-2].to_string();
    ct_string.push_str("]");
    writeln!(proverinfo, "cts = {}", ct_string)?;

    writeln!(proverinfo, "msg = [\"{}\", \"{}\", \"{}\"]", tally[0], tally[1], tally[2])?;

    let sk_string = sk.to_string();
    println!("SK: {}", sk_string);
    writeln!(proverinfo, "sk = \"{}\"", &sk_string)?;

    return Ok(());
}

fn gen_r_vote_master() -> io::Result<()>  {

    // enc(T_v) is stored in a merkle tree of all the delegates' voting powers
    // For R_vote, we're trying to send a triple of (enc(0, r1),rerand(enc(T_v),r2),enc(0,r))

    let solidity_path = "vote_inputs.txt";
    let iiopts = OpenOptions::new().create(true).append(true).open(solidity_path)?;
    let mut inputsarray = io::BufWriter::new(iiopts);

    let prover_path = "vote_Prover.txt";
    let piopts = OpenOptions::new().create(true).append(true).open(prover_path)?;
    let mut proverinfo = io::BufWriter::new(piopts);

    let rust_prover_path = "rust_prover.txt";
    let riopts = OpenOptions::new().create(true).append(true).open(rust_prover_path)?;
    let mut witnessmap = io::BufWriter::new(riopts);
    let mut witness_ctr = 1;


    let mut rng = rand::thread_rng();

    let sk = bjj_ah_elgamal::get_sk();
    let pk = bjj_ah_elgamal::sk_to_pk(&sk);

    // pk_enc_x, pk_enc_y
    writeln!(inputsarray, "// pk_enc_x, pk_enc_y:")?;
    let mut input_ctr = 0;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_x_str(&pk))?;
    input_ctr += 1;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_y_str(&pk))?;
    input_ctr += 1;

    let mut randomness_str = "[".to_owned();

    let mut random_states = Vec::new();
    for i in 0..3 {
        let r = rng.gen_range(1..10).to_bigint().unwrap();
        randomness_str.push_str(&("\"".to_owned() + &r.to_string() + "\", "));

        random_states.push(r);
    }
    randomness_str = randomness_str[0..randomness_str.len()-2].to_string();
    randomness_str.push_str("]");



    let vote_choice = 1;  // 0 = Y, 1 = N, 2 = A
    let voting_power = 300;

    writeln!(witnessmap, "initial_witness.insert(Witness({}), FieldElement::from({}_u128));", 1, vote_choice as u128)?;
    witness_ctr += 1;

    let vote_encryption = bjj_ah_elgamal::encrypt(&voting_power, &pk, &BigInt::from_str("2").unwrap());


    // enc_delegate_voting_power
    writeln!(inputsarray, "// enc_delegate_voting_power:")?;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_x_str(&vote_encryption.0.affine()))?;
    input_ctr += 1;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_y_str(&vote_encryption.0.affine()))?;
    input_ctr += 1;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_x_str(&vote_encryption.1.affine()))?;
    input_ctr += 1;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, bjj_ah_elgamal::point_y_str(&vote_encryption.1.affine()))?;
    input_ctr += 1;


    // vote NO (Y/N/A)
    // so at position 1, we store a rerandomization of our voting power
    let vote_encs = vec![  bjj_ah_elgamal::encrypt(&0, &pk, &random_states[0]),
                                                                    bjj_ah_elgamal::rerandomize(&pk, &vote_encryption, &random_states[1]),
                                                                    //bjj_ah_elgamal::encrypt(&voting_power, &pk, &random_states[1]),
                                                                    bjj_ah_elgamal::encrypt(&0, &pk, &random_states[2])];
    

    let enc_v_power_str: String = "[\"".to_owned() +    &bjj_ah_elgamal::point_x_str(&vote_encryption.0.affine()) + "\", \"" + 
                                                        &bjj_ah_elgamal::point_y_str(&vote_encryption.0.affine()) + "\", \"" +
                                                        &bjj_ah_elgamal::point_x_str(&vote_encryption.1.affine()) + "\", \"" +
                                                        &bjj_ah_elgamal::point_y_str(&vote_encryption.1.affine()) + "\"]";

    // turns encs to leaves vector, make encryptions string

    let mut encryptions = "[".to_owned();

    // DON'T LOOP OVER ENCS HERE -- ENCS is (Y,N,A). WE WANT TO LOOP OVER
    // DELEGATE VOTE COUNTS.


    writeln!(inputsarray, "// encryptions:")?;
    for e in vote_encs.iter() {

        let e_x =  bjj_ah_elgamal::point_x_str(&e.0.affine());
        let e_y =  bjj_ah_elgamal::point_y_str(&e.0.affine());
        let v_x =  bjj_ah_elgamal::point_x_str(&e.1.affine());
        let v_y =  bjj_ah_elgamal::point_y_str(&e.1.affine());
        
        encryptions.push_str(&("\"".to_owned() + &e_x + "\", "));
        encryptions.push_str(&("\"".to_owned() + &e_y + "\", "));
        encryptions.push_str(&("\"".to_owned() + &v_x + "\", "));
        encryptions.push_str(&("\"".to_owned() + &v_y + "\", "));

        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, e_x)?;
        input_ctr += 1;
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, e_y)?;
        input_ctr += 1;
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, v_x)?;
        input_ctr += 1;
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, v_y)?;
        input_ctr += 1;
        
        //bjj_ah_elgamal::print_point(&e.0.affine(), "e");
        //bjj_ah_elgamal::print_point(&e.1.affine(), "v");
        //inp.push(vec![e.0.affine().x, e.0.affine().y, e.1.affine().x, e.1.affine().y]);
    }
    encryptions = encryptions[0..encryptions.len()-2].to_string();
    encryptions.push_str("]");


    // manufacture merkle tree
    let mut inp_leaves = Vec::new();
    let delegate_idx = 3;

    // delegate_idx
    let d_idx_string = format!("{:x}", delegate_idx);
    let padding = "0x".to_string() + &String::from_utf8(vec![b'0'; 64-d_idx_string.len()]).unwrap();
    writeln!(inputsarray, "// delegate_idx:")?;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, padding + &d_idx_string)?;
    input_ctr += 1;

    for i in 0..4 {
        if i == delegate_idx {
            
            inp_leaves.push(vec![vote_encryption.0.affine().x, vote_encryption.0.affine().y, vote_encryption.1.affine().x, vote_encryption.1.affine().y]);
        } else {
            let other_enc = bjj_ah_elgamal::encrypt(&(i+1), &pk, &BigInt::from_str("3").unwrap());
            inp_leaves.push(vec![other_enc.0.affine().x, other_enc.0.affine().y, other_enc.1.affine().x, other_enc.1.affine().y])
        }
    }


    // each of these inputs must be 4s of Frs (e_x, e_y, v_x, v_y). The entry
    // has to be hash4'd. Make the 'input' to merkle helper a vector of
    // vectors, usually the secondary vectors are just 1-vectors, here they'd
    // be 4-vectors. Then, we pass in raw encryption quadss as inputs
    let (root, hashpath) = merklehelper::gen_proof_padded(
        &inp_leaves,
        20, delegate_idx).unwrap();

    // write merkle information to verifier inputs
    let root_string = root.to_string();
    writeln!(inputsarray, "// root_eid:")?;
    writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, &root_string[3..root_string.len()-1])?;
    input_ctr += 1;

    writeln!(inputsarray, "// voting_power_hashpath:")?;
    for m in hashpath.iter() {
        let m_str = m.to_string();
        writeln!(inputsarray, "inputs[{}] = bytes32({});", input_ctr, &m_str[3..m_str.len()-1])?;
        input_ctr += 1;
    }

    // write all information to Prover.toml
    writeln!(proverinfo, "delegate_idx = \"{}\"", delegate_idx)?;
    writeln!(proverinfo, "enc_delegate_voting_power = {}", enc_v_power_str)?;
    writeln!(proverinfo, "encryptions = {}", encryptions)?;
    writeln!(proverinfo, "i = \"{}\"", vote_choice)?;
    writeln!(proverinfo, "pk_enc_x = \"{}\"", bjj_ah_elgamal::point_x_str(&pk))?;
    writeln!(proverinfo, "pk_enc_y = \"{}\"", bjj_ah_elgamal::point_y_str(&pk))?;
    writeln!(proverinfo, "randomness = {}", randomness_str)?;

    let root_string = root.to_string();
    writeln!(proverinfo, "root_eid = \"{}\"", &root_string[3..root_string.len()-1])?;

    // convert hashpath to string
    let mut prover_hp_string = "[".to_owned();
    for m in hashpath.iter() {
        let mut cur = m.to_string();
        cur = cur[3..cur.len()-1].to_string();
        prover_hp_string.push_str(&("\"".to_owned() + &cur + "\", "))
    }
    prover_hp_string = prover_hp_string[0..prover_hp_string.len()-2].to_string();
    prover_hp_string.push_str("]");

    writeln!(proverinfo, "voting_power_hashpath = {}", prover_hp_string)?;

    return Ok(());
}

fn gen_r_del_master() -> io::Result<()> {
    let solidity_path = "del_inputs.txt";
    let iiopts = OpenOptions::new().create(true).append(true).open(solidity_path)?;
    let mut inputsarray = io::BufWriter::new(iiopts);

    let prover_path = "del_Prover.txt";
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
    let anonymity_set_size = 25;

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
        &vec![vec![Fr::from_str("0").unwrap()],
        vec![Fr::from_str("1").unwrap()],
        vec![Fr::from_str(&tv.to_string()).unwrap()],
        vec![Fr::from_str("2").unwrap()]],
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