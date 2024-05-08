use bitcoin_hashes::{sha256, Hash};

pub struct Forest {
    pub roots: Vec<[u8; 33]>, // here the first byte encodes the height of the tree, the rest 32 are the hash
}

pub struct Proof {
    pub tree_index: usize,

    // here the first byte is either zero or one, for ordering the hashing pair
    // zero means 'prepend this path item to the thing you have', one means 'append'
    pub merkle_path: Vec<[u8; 33]>,
}

impl Forest {
    pub fn new() -> Self {
        Forest { roots: Vec::new() }
    }

    pub fn add(&mut self, entry: &[u8]) -> ([u8; 32], Proof) {
        let hash = sha256::Hash::hash(entry);
        let proof = self.add_hash(hash.as_byte_array());
        (*hash.as_byte_array(), proof)
    }

    pub fn add_hash(&mut self, hash: &[u8; 32]) -> Proof {
        let mut new_merkle_root = vec![0u8; 33];
        new_merkle_root[1..33].copy_from_slice(hash);

        let mut proof = Proof {
            tree_index: 0,
            merkle_path: Vec::with_capacity(32),
        };

        // the log entry we're adding is by default a new merkle root at level 0
        let mut level = 0;
        loop {
            // check if we can merge with the previous one
            match self.roots.last() {
                Some(prev_root) if prev_root[0] == level => {
                    let mut path_item = vec![0u8; 33];
                    path_item[1..33].copy_from_slice(&prev_root[1..33]);
                    // path_item[0] = 0; // no need to set the first byte to zero as that is already set

                    proof.merkle_path.push(path_item.try_into().unwrap());

                    // yes, we can
                    let mut combined_merkle = vec![0u8; 64];
                    combined_merkle[0..32].copy_from_slice(&prev_root[1..33]);
                    combined_merkle[32..64].copy_from_slice(&new_merkle_root[1..33]);

                    new_merkle_root[1..33]
                        .copy_from_slice(sha256::Hash::hash(&combined_merkle).as_byte_array());
                    new_merkle_root[0] = level + 1;

                    // remove that previous as we will replace it
                    self.roots.remove(self.roots.len() - 1);

                    // increase the level of the thing we're adding and check again
                    level += 1;

                    continue;
                }
                _ => {
                    proof.tree_index = self.roots.len();
                    self.roots.push(new_merkle_root.try_into().unwrap());
                    return proof;
                }
            }
        }
    }

    pub fn check_presence(&self, entry: [u8; 32], proof: &Proof) -> bool {
        self.roots.get(proof.tree_index).map_or(false, |root| {
            let mut current_value = entry;
            let mut combined_merkle = vec![0u8; 64];
            for path_item in &proof.merkle_path {
                if path_item[0] == 0 {
                    combined_merkle[0..32].copy_from_slice(&path_item[1..33]);
                    combined_merkle[32..64].copy_from_slice(&current_value);
                } else {
                    combined_merkle[0..32].copy_from_slice(&current_value);
                    combined_merkle[32..64].copy_from_slice(&path_item[1..33]);
                }

                current_value = *sha256::Hash::hash(&combined_merkle).as_byte_array();
            }

            current_value == root[1..33]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_building_manual() {
        let mut forest = Forest::new();
        forest.add(&vec![1, 2, 3, 4, 5]);
        assert_eq!(forest.roots.len(), 1, "length 1 at 1");
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        assert_eq!(forest.roots.len(), 2, "length 2 at 3");
        forest.add(&vec![1, 2, 3, 4, 5]);
        assert_eq!(forest.roots.len(), 1, "length 1 at 4");
        assert_eq!(forest.roots[0][0], 2, "level 2 at 4");
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        assert_eq!(forest.roots.len(), 3, "length 3 at 12");
        assert_eq!(forest.roots[0][0], 3, "level 3 at 12");
    }

    #[test]
    fn tree_building() {
        let mut forest = Forest::new();
        for i in 0..(u64::pow(2, 16) - 1) {
            forest.add(format!("entry:{}", i).as_bytes());
        }
        assert_eq!(forest.roots.len(), 16, "16 trees right before level 16");
        forest.add("last".as_bytes());
        assert_eq!(forest.roots.len(), 1, "perfect single tree with 16 levels");
        assert_eq!(forest.roots[0][0], 16, "level 16 after 2**16 entries");
    }

    #[test]
    fn correct_hashing() {
        let mut forest1 = Forest::new();
        let h = sha256::Hash::hash(&vec![1, 2, 3, 4, 5]);
        forest1.add_hash(h.as_byte_array());

        assert_eq!(
            forest1.roots[0],
            [
                0u8, 116u8, 248u8, 31u8, 225u8, 103u8, 217u8, 155u8, 76u8, 180u8, 29u8, 109u8,
                12u8, 205u8, 168u8, 34u8, 120u8, 202u8, 238u8, 159u8, 62u8, 47u8, 37u8, 213u8,
                229u8, 163u8, 147u8, 111u8, 243u8, 220u8, 236u8, 96u8, 208u8,
            ]
        );

        forest1.add_hash(h.as_byte_array());
        forest1.add_hash(h.as_byte_array());
        forest1.add_hash(h.as_byte_array());
        forest1.add_hash(h.as_byte_array());

        let mut forest2 = Forest::new();
        forest2.add(&vec![1, 2, 3, 4, 5]);
        forest2.add(&vec![1, 2, 3, 4, 5]);
        forest2.add(&vec![1, 2, 3, 4, 5]);
        forest2.add(&vec![1, 2, 3, 4, 5]);
        forest2.add(&vec![1, 2, 3, 4, 5]);

        assert_eq!(forest1.roots, forest2.roots);
        assert_eq!(
            forest2.roots[0],
            [
                2u8, 217u8, 21u8, 129u8, 3u8, 237u8, 23u8, 184u8, 184u8, 149u8, 37u8, 236u8, 24u8,
                71u8, 86u8, 103u8, 102u8, 187u8, 212u8, 251u8, 124u8, 220u8, 154u8, 90u8, 54u8,
                144u8, 46u8, 225u8, 145u8, 124u8, 70u8, 214u8, 70u8,
            ]
        );
    }

    #[test]
    fn proofs() {
        let mut forest = Forest::new();
        forest.add(&vec![1, 2, 3, 4, 5]);
        let (hash, proof) = forest.add(&vec![0, 0, 0, 0, 0]);
        assert_eq!(proof.tree_index, 0, "proof tree index");
        assert_eq!(proof.merkle_path.len(), 1, "merkle path size");
        assert_eq!(
            forest.check_presence(hash, &proof),
            true,
            "presence should be confirmed"
        );
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        forest.add(&vec![1, 2, 3, 4, 5]);
        let (hash, proof) = forest.add(&vec![1, 2, 3, 4, 5]);
        assert_eq!(proof.tree_index, 0, "proof tree index");
        assert_eq!(proof.merkle_path.len(), 3, "merkle path size");
        assert_eq!(
            forest.check_presence(hash, &proof),
            true,
            "presence should be confirmed"
        );

        let (hash, _) = forest.add(&vec![0, 0, 0, 0, 0]);
        assert_eq!(
            forest.check_presence(hash, &proof),
            false,
            "proof for a different entry shouldn't work"
        );
    }
}
