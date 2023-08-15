use libsecp256k1::{*, curve::*};
use rand::RngCore;

// pub fn debug() {
//   let gen_ctx = &ECMULT_GEN_CONTEXT;
//   let mul_ctx = &ECMULT_CONTEXT;

//   let mut g_a = Jacobian::default();
//   let alpha = Scalar::from_int(3);
//   let beta = Scalar::from_int(2);
//   gen_ctx.ecmult_gen(&mut g_a, &alpha); // g * a

//   let mut g_a_b = Jacobian::default();
//   mul_ctx.ecmult_const(&mut g_a_b, &Affine::from_gej(&g_a), &beta); // this is affine * scalar!

//   let mut g_x = Jacobian::default();
//   let x = Scalar::from_int(5);
//   let y = Scalar::from_int(4);
//   gen_ctx.ecmult_gen(&mut g_x, &x); // g * a

//   let mut g_x_y = Jacobian::default();
//   mul_ctx.ecmult_const(&mut g_x_y, &Affine::from_gej(&g_x), &y); // this is affine * scalar!

//   let msg = 1u32;
//   let mut t = Scalar::from_int(msg);
//   let mut g_m = Jacobian::default();
//   gen_ctx.ecmult_gen(&mut g_m, &t);

//   let gab_p_gm = g_a_b.add_var(&g_m, None);
//   let gxy_p_gab_p_gm = gab_p_gm.add_var(&g_x_y, None);
//   let sub_factor = g_a_b.neg();
//   let should_be_gm = gab_p_gm.add_var(&sub_factor, None);

//   let before = Affine::from_gej(&g_m);
//   let after = Affine::from_gej(&should_be_gm);
//   println!("test");
// }

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

pub fn encrypt(msg: &u32, pk: Jacobian) -> (Jacobian, Jacobian) {
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let beta: Scalar = Scalar::from_int(rand::random());

  let mut v: Jacobian = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut v, &beta); // g * sk2 = v

  let mut w: Jacobian = Jacobian::default();
  mul_context.ecmult_const(&mut w, &Affine::from_gej(&pk), &beta); // pk * sk2 = g * sk * sk2 = w

  let mut g_m = Jacobian::default();  // put message on curve
  gen_mul_context.ecmult_gen(&mut g_m, &Scalar::from_int(*msg));

  let e = w.add_var(&g_m, None);
  return (e, v)
}

fn test_equality(p1: &mut Affine, p2: &mut Affine) -> bool {
  return p1.x.eq_var(&p2.x) && p1.y.eq_var(&p2.y);
}

pub fn decrypt(sk: Scalar, vs: &Vec<Jacobian>, e: Jacobian) -> Jacobian {
  // sk = alpha
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;
  let mut g_m = e.clone();

  for v in vs.iter() {
    let mut w: Jacobian = Jacobian::default();
    mul_context.ecmult_const(&mut w, &Affine::from_gej(v), &sk); // g * beta * alpha = w

    w = w.neg();

    g_m = g_m.add_var(&w, None);  // add the negation, so subtract w
  }
  return g_m;
}

pub fn rerandomize(pk: Jacobian, c: (Jacobian, Jacobian)) -> (Jacobian, Jacobian) {
  let (e, v) = c;
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let r = Scalar::from_int(rand::random());
  let mut g_r = Jacobian::default();
  let mut pk_r = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut g_r, &r);
  mul_context.ecmult_const(&mut pk_r, &Affine::from_gej(&pk), &r);

  let v_rerand = v.add_var(&g_r, None);
  let e_rerand = e.add_var(&pk_r, None);
  return (e_rerand, v_rerand)
}


pub fn decrypt2 (sk: Scalar, v: Jacobian, e: Jacobian) -> Jacobian {
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let mut w: Jacobian = Jacobian::default();
  mul_context.ecmult_const(&mut w, &Affine::from_gej(&v), &sk); // g * beta * alpha = w

  w = w.neg();

  let g_m = e.add_var(&w, None);  // add the negation, so subtract w
  return g_m;
}
pub fn extract_number(g_m: Jacobian) -> u32 {
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;

  let mut m: u32 = 1;
  let mut cur = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut cur, &Scalar::from_int(1));
  let mut g = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut g, &Scalar::from_int(1));
  for _ in 1..1_000_000 {
    if test_equality(&mut Affine::from_gej(&cur), &mut Affine::from_gej(&g_m)) {
      break;
    }

    cur = cur.add_var(&g, None);
    m += 1;
  }

  return m;
}

pub fn add_encryptions(e1: &Jacobian, e2:&Jacobian) -> Jacobian {
  return e1.add_var(e2, None);
}