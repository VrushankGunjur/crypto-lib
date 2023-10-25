use ff::PrimeField;
use poseidon_rs::{Fr, Poseidon};
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
// #[derive(Debug, Clone)]
// pub struct TrieNode {
//   val: Option<[u8; 32]>,  // the actual enk... should probably be [u8; 32]
//   hash: [u8; 32],
//   left: Option<TrieNodeRef>,
//   right: Option<TrieNodeRef>,
// }

// type TrieNodeRef = Rc<RefCell<TrieNode>>;

// calculate the hashes, return (root, hashpath)
pub fn gen_proof(input: &Vec<Fr>, hashpath_len: usize, target_idx: u32) -> Option<(Fr, Vec<Fr>)> {
    let hasher = poseidon_rs::Poseidon::new();
    let input_len = input.len();
    let target_num_leaves = u32::pow(2, hashpath_len as u32) as usize;

    if input_len > target_num_leaves {
        // throw an error
        return None; //Err("Invalid Hashpath Length");  // can't make a hashpath this small for the input data
    }

    // instead, make a subtree of 0's. Easy to compute that root, since it's
    // symmetric. 
    //let leaves = input.copy();
    let mut leaves = input.to_owned();
    leaves.extend(vec![Fr::from_str("0").unwrap(); target_num_leaves - input_len]);
    println!("{}", leaves.len());

    // first, hash all the leaves. Should this be of type Fr?
    let mut cur = vec![Fr::from_str("0").unwrap(); leaves.len()];
    for i in 0..leaves.len() {
        cur[i] = hasher.hash(vec![leaves[i]]).unwrap();
    }
    
    let mut hashpath = vec![Fr::from_str("0").unwrap(); hashpath_len];
    let mut level_pos = target_idx;

    for h_i in 0..hashpath_len {
        if level_pos % 2 == 0 {
            hashpath[h_i] = cur[(level_pos + 1) as usize];
        } else {
            hashpath[h_i] = cur[(level_pos - 1) as usize];
        }
        let mut new_leaves = vec![Fr::from_str("0").unwrap(); cur.len() / 2];
        for (i, l) in cur.chunks(2).enumerate() {
            new_leaves[i] = hasher.hash(vec![l[0], l[1]]).unwrap();
        }
        cur = new_leaves;
        level_pos /= 2;
    }

    return Some((cur[0], hashpath));
}

// fn u8_array_to_bool_array(input: [u8; 32]) -> [bool; 256] {
//   let mut output = [false; 256];
//   for (i, &byte) in input.iter().enumerate() {
//       for bit in 0..8 {
//           output[i * 8 + bit] = (byte & (1 << bit)) != 0;
//       }
//   }
//   return output;
// }

// fn bool_array_to_u8_array(input: [bool; 256]) -> [u8; 32] {
//   let mut output = [0u8; 32];
//   for (i, &bit) in input.iter().enumerate() {
//       if bit {
//           let byte_index = i / 8;
//           let bit_index = i % 8;
//           output[byte_index] |= 1 << bit_index;
//       }
//   }
//   return output;
// }


// fn insert_leaf(root: TrieNodeRef, bits: [bool; 256], i: u32) {
//   if i == 256 {
//     // we're at the leaf, no more bits to account for
//     root.val = Some(bool_array_to_u8_array(bits));
//   }
//   else if bits[i] == 0 {
//     if root.left == None {
//       // not quite this easy... see https://github.com/anupj/Data-Structures-in-Rust/blob/main/binary_tree/tree_height/src/lib.rs
//       root.left = TrieNode{val: None, hash: None, left: None, right: None};
//     }
//     insert_leaf(root.left)
//   }
// }

// // insert the leaves, then call merkleize
// pub fn build_trie(l: Vec<[u8; 32]>) {

//   let root = TrieNode{val: None, hash: None, left: None, right: None};

//   for enk_i in l.iter() {
//     // insert it

//   }
// }