use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};

#[derive(Debug, Clone)]
pub struct TrieNode {
  val: Option<[u8; 32]>,  // the actual enk... should probably be [u8; 32]
  hash: [u8; 32],
  left: Option<TrieNodeRef>,
  right: Option<TrieNodeRef>,
}

type TrieNodeRef = Rc<RefCell<TrieNode>>;

// calculate the hashes
fn merkleize() {}

fn u8_array_to_bool_array(input: [u8; 32]) -> [bool; 256] {
  let mut output = [false; 256];
  for (i, &byte) in input.iter().enumerate() {
      for bit in 0..8 {
          output[i * 8 + bit] = (byte & (1 << bit)) != 0;
      }
  }
  return output;
}

fn bool_array_to_u8_array(input: [bool; 256]) -> [u8; 32] {
  let mut output = [0u8; 32];
  for (i, &bit) in input.iter().enumerate() {
      if bit {
          let byte_index = i / 8;
          let bit_index = i % 8;
          output[byte_index] |= 1 << bit_index;
      }
  }
  return output;
}


fn insert_leaf(root: TrieNodeRef, bits: [bool; 256], i: u32) {
  if i == 256 {
    // we're at the leaf, no more bits to account for
    root.val = Some(bool_array_to_u8_array(bits));
  }
  else if bits[i] == 0 {
    if root.left == None {
      // not quite this easy... see https://github.com/anupj/Data-Structures-in-Rust/blob/main/binary_tree/tree_height/src/lib.rs
      root.left = TrieNode{val: None, hash: None, left: None, right: None};
    }
    insert_leaf(root.left)
  }
}

// insert the leaves, then call merkleize
pub fn build_trie(l: Vec<[u8; 32]>) {

  let root = TrieNode{val: None, hash: None, left: None, right: None};

  for enk_i in l.iter() {
    // insert it

  }
}