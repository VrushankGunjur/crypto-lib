use libsecp256k1::{*, curve::*};

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

pub fn decrypt(sk: Scalar, c: (Jacobian, Jacobian)) -> u32 {
  let (e, v) = c;

  let mul_context: &ECMultContext = &ECMULT_CONTEXT;
  let mut g_m: Jacobian = e.clone();

  let mut w: Jacobian = Jacobian::default();
  mul_context.ecmult_const(&mut w, &Affine::from_gej(&v), &sk); // g * beta * alpha = w

  w = w.neg();
  g_m = g_m.add_var(&w, None);  // add the negation, so subtract w
  
  return extract_number(g_m);
}

pub fn rerandomize(pk: Jacobian, c: (Jacobian, Jacobian)) -> (Jacobian, Jacobian) {
  let (e, v) = c;
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let r: Scalar = Scalar::from_int(rand::random());
  let mut g_r: Jacobian = Jacobian::default();
  let mut pk_r: Jacobian = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut g_r, &r);
  mul_context.ecmult_const(&mut pk_r, &Affine::from_gej(&pk), &r);

  let v_rerand: Jacobian = v.add_var(&g_r, None);
  let e_rerand: Jacobian = e.add_var(&pk_r, None);
  return (e_rerand, v_rerand)
}


pub fn decrypt2 (sk: Scalar, v: Jacobian, e: Jacobian) -> u32 {
  let mul_context: &ECMultContext = &ECMULT_CONTEXT;

  let mut w: Jacobian = Jacobian::default();
  mul_context.ecmult_const(&mut w, &Affine::from_gej(&v), &sk); // g * beta * alpha = w

  w = w.neg();

  let g_m = e.add_var(&w, None);  // add the negation, so subtract w
  return extract_number(g_m);
}

fn extract_number(g_m: Jacobian) -> u32 {
  let gen_mul_context: &ECMultGenContext = &ECMULT_GEN_CONTEXT;

  let mut m: u32 = 1;
  let mut cur: Jacobian = Jacobian::default();
  gen_mul_context.ecmult_gen(&mut cur, &Scalar::from_int(1));
  let mut g: Jacobian = Jacobian::default();
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

pub fn add_encryptions(cs: &Vec<(Jacobian, Jacobian)>) -> (Jacobian, Jacobian) {
  let mut e_sum = cs[0].0;
  let mut v_sum = cs[0].1;
  for (e,v) in cs.iter().skip(1) {
    e_sum = e_sum.add_var(e, None);
    v_sum = v_sum.add_var(v, None);
  }
  return (e_sum, v_sum);
}