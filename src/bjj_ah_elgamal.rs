use babyjubjub_rs::*;
use lazy_static::lazy_static;
use ff::*;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};

//use poseidon_rs::Fr;
//pub type Fr = poseidon_rs::Fr; // alias


lazy_static! {
  static ref B8: Point = Point {
    x: Fr::from_str(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    )
    .unwrap(),
    y: Fr::from_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .unwrap(),
};
}

fn print_point(p: &Point, name: &str) {
  println!("{}.x: {}", name, p.x.to_string());
  println!("{}.y: {}", name, p.y.to_string());
}

fn gen_rand_bigint () -> BigInt {
  let mut rng = rand::thread_rng();
  let low =  1.to_bigint().unwrap();
  let high = 1000000.to_bigint().unwrap();
  return rng.gen_bigint_range(&low, &high);
}

pub fn get_sk () -> BigInt {
  return gen_rand_bigint();

  // let mut rng = rand::thread_rng();
  // let mut result = String::with_capacity(20);

  // for _ in 0..20 {
  //     let random_digit = rng.gen_range(1..=9);  // Generate a random digit from 1 to 9
  //     result.push_str(&random_digit.to_string());  // Convert the digit to a string and append
  // }

  // return Fr::from_str(result.as_str()).unwrap();
}

pub fn get_point(power: &u32) -> Point {
    return B8.mul_scalar(&BigInt::from_bytes_be(Sign::Plus, &power.to_be_bytes())); 
}

pub fn sk_to_pk (sk: &BigInt) -> Point {
  let r: Point = B8.mul_scalar(sk);
  return r;
}

pub fn encrypt(msg: &u32, pk: &Point) -> (Point, Point) {
  let adjusted_msg = msg;
  let beta = gen_rand_bigint();
  let v = B8.mul_scalar(&beta);  // g * sk2 = v

  let w = pk.mul_scalar(&beta); // pk * sk2 = g * sk * sk2 = w

  let g_m = B8.mul_scalar(&BigInt::from_bytes_be(Sign::Plus, &adjusted_msg.to_be_bytes()));  // put msg on curve
  let e = w.projective().add(&g_m.projective());

  return (e.affine(), v);
}

fn test_equality(p1: &mut Point, p2: &mut Point) -> bool {
  return p1.x.eq(&p2.x) && p1.y.eq(&p2.y);
}

pub fn decrypt(sk: &BigInt, c: (Point, Point)) -> u32 {
  let (e, v) = c;

  print_point(&e, "e");
  print_point(&v, "v");
  println!("sk: {}", sk.to_string());

  let mut g_m: Point = e.clone();

  let mut w = v.mul_scalar(&sk);
  w.x.negate(); // negate point

  g_m = g_m.projective().add(&w.projective()).affine();  // add the negation, so subtract w from e

  //let m: u32 = extract_number(&mut g_m);
  let m = discrete_log(&mut g_m);
  println!("m: {}", m);
  return m;
}

pub fn rerandomize(pk: &Point, c: (Point, Point)) -> (Point, Point) {

  let (e, v) = c;
  //print_point(pk, "pk");
  //print_point(&e, "e");
  //print_point(&v, "v");

  let r = gen_rand_bigint();
  //println!("r: {}", r.to_string());


  let g_r = B8.mul_scalar(&r);
  let pk_r = pk.mul_scalar(&r);

  let v_rerand = v.projective().add(&g_r.projective()).affine();
  let e_rerand = e.projective().add(&pk_r.projective()).affine();

  //print_point(&v_rerand, "v_rerand");
  //print_point(&e_rerand, "e_rerand");
  return (e_rerand, v_rerand)
}

/*
    Discrete log calculates log_g(g^m) = m. As an implementation detail of the encryption scheme, it actually returns m-1.
*/
pub fn discrete_log(g_m: &mut Point) -> u32 {
    let q: u32 = 16_192_576;
    //let t = (q as f64).sqrt() as u32;
    let t = 4024;
    println!("q: {}, t: {}", q, t);

    //let num_big_steps = ((q/t) as u32) * t;
    let mut ring: Vec<Point> = vec![B8.clone(); (t+1) as usize];
    for i in 1..(t+1) {
        // g^1, g^t, g^2t, g^3t, ...
        //println!("ring[{}] = {}", i,  t *i);
        ring[i as usize] = ring[i as usize].mul_scalar(&(t * i).to_bigint().unwrap());
    }

    let mut small_steps: Vec<Point> = vec![B8.clone(); t as usize];
    let mut cur_step: Point = g_m.clone();
    let g: PointProjective = B8.clone().projective();
    small_steps[0] = cur_step.clone();
    for i in 1..t {
        cur_step = cur_step.projective().add(&g).affine();
        small_steps[i as usize] = cur_step.clone();
        //small_steps[i as usize] = g_m.mul_scalar(&i.to_bigint().unwrap());
    }

    // check if smallsteps[i] == ring[j]
    for k in 1..(t+1) {
        for i in 0..t{
            if test_equality(&mut ring[k as usize], &mut small_steps[i as usize]) {
                return (k * t) - i; // -1 adjustion factor to account for no encryption of 0
            }
        }
    } 
    return 0;
}

/*
    Naive discrete log
*/
fn extract_number(g_m: &mut Point) -> u32 {

  let mut m: u32 = 1;
  //let mut cur: Point = B8.mul_scalar(&BigInt::new(Sign::Plus, vec![1]));  // g^1
  let mut cur = B8.clone();
  let g = B8.clone().projective();

  for _ in 1..1_000_000 {
    if test_equality(&mut cur, g_m) {
      break;
    }

    cur = cur.projective().add(&g).affine();
    m += 1;
  }

  return m; // -1 to adjust
}

pub fn add_encryptions(cs: &Vec<(Point, Point)>) -> (Point, Point) {
  let mut e_sum = cs[0].0.projective();
  let mut v_sum = cs[0].1.projective();
  for (e,v) in cs.iter().skip(1) {
    e_sum = e_sum.add(&e.projective());
    v_sum = v_sum.add(&v.projective());
  }
  return (e_sum.affine(), v_sum.affine());
}