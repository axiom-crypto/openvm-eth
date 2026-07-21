use revm_primitives::{b256, keccak256, B256};

use crate::{
    node::{BranchChildId, NodeData},
    Error, Mpt,
};

trait RlpBytes {
    /// Returns the RLP-encoding.
    fn to_rlp(&self) -> Vec<u8>;
}

impl<T> RlpBytes for T
where
    T: alloy_rlp::Encodable,
{
    #[inline]
    fn to_rlp(&self) -> Vec<u8> {
        let rlp_length = self.length();
        let mut out = Vec::with_capacity(rlp_length);
        self.encode(&mut out);
        debug_assert_eq!(out.len(), rlp_length);
        out
    }
}

#[test]
fn test_empty() {
    let bump = bumpalo::Bump::new();
    let trie = Mpt::new(&bump);

    assert!(trie.is_empty());
    let expected = b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    assert_eq!(expected, trie.hash());
}

#[test]
fn test_empty_key() -> Result<(), Error> {
    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    trie.insert(&[], b"empty")?;
    assert_eq!(trie.get(&[])?, Some(b"empty".as_ref()));
    assert!(trie.delete(&[])?);

    Ok(())
}

#[test]
fn test_branch_value() {
    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);
    trie.insert(b"do", b"verb").unwrap();
    // leads to a branch with value which is not supported
    trie.insert(b"dog", b"puppy").unwrap_err();
}

#[test]
fn test_insert() -> Result<(), Error> {
    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    let key_vals = vec![
        ("painting", "place"),
        ("guest", "ship"),
        ("mud", "leave"),
        ("paper", "call"),
        ("gate", "boast"),
        ("tongue", "gain"),
        ("baseball", "wait"),
        ("tale", "lie"),
        ("mood", "cope"),
        ("menu", "fear"),
    ];
    for (key, val) in &key_vals {
        assert!(trie.insert(key.as_bytes(), val.as_bytes())?);
    }

    let expected = b256!("2bab6cdf91a23ebf3af683728ea02403a98346f99ed668eec572d55c70a4b08f");
    assert_eq!(expected, trie.hash());

    for (key, value) in &key_vals {
        let retrieved = trie.get(key.as_bytes())?.unwrap();
        assert_eq!(retrieved, value.as_bytes());
    }

    // check inserting duplicate keys
    assert!(trie.insert(key_vals[0].0.as_bytes(), b"new")?);
    assert!(!trie.insert(key_vals[0].0.as_bytes(), b"new")?);

    Ok(())
}

#[test]
fn test_keccak_trie() -> Result<(), Error> {
    const N: usize = 512;

    // insert
    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    for i in 0..N {
        assert!(trie.insert_rlp(keccak256(i.to_be_bytes()).as_slice(), i)?);

        // check hash against trie build in reverse
        let bump2 = bumpalo::Bump::new();
        let mut trie2 = Mpt::new(&bump2);
        for j in (0..=i).rev() {
            trie2.insert_rlp(keccak256(j.to_be_bytes()).as_slice(), j)?;
        }
        assert_eq!(trie.hash(), trie2.hash());
    }

    let expected = b256!("7310027edebdd1f7c950a7fb3413d551e85dff150d45aca4198c2f6315f9b4a7");
    assert_eq!(trie.hash(), expected);

    // get
    for i in 0..N {
        assert_eq!(trie.get_rlp(keccak256(i.to_be_bytes()).as_slice())?, Some(i));
        assert!(trie.get(keccak256((i + N).to_be_bytes()).as_slice())?.is_none());
    }

    // delete
    for i in 0..N {
        assert!(trie.delete(keccak256(i.to_be_bytes()).as_slice())?);

        let bump2 = bumpalo::Bump::new();
        let mut trie2 = Mpt::new(&bump2);
        for j in ((i + 1)..N).rev() {
            trie2.insert_rlp(keccak256(j.to_be_bytes()).as_slice(), j)?;
        }
        assert_eq!(trie.hash(), trie2.hash());
    }
    assert!(trie.is_empty());

    Ok(())
}

#[test]
fn test_index_trie() -> Result<(), Error> {
    const N: usize = 512;

    // insert
    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    for i in 0..N {
        assert!(trie.insert_rlp(&i.to_rlp(), i)?);

        // check hash against trie build in reverse
        let bump2 = bumpalo::Bump::new();
        let mut trie2 = Mpt::new(&bump2);
        for j in (0..=i).rev() {
            trie2.insert_rlp(&j.to_rlp(), j)?;
        }
        assert_eq!(trie.hash(), trie2.hash());
    }

    // get
    for i in 0..N {
        assert_eq!(trie.get_rlp(&i.to_rlp())?, Some(i));
        assert!(trie.get(&(i + N).to_rlp())?.is_none());
    }

    // delete
    for i in 0..N {
        assert!(trie.delete(&i.to_rlp()).unwrap());

        let bump2 = bumpalo::Bump::new();
        let mut trie2 = Mpt::new(&bump2);
        for j in ((i + 1)..N).rev() {
            trie2.insert_rlp(&j.to_rlp(), j)?;
        }
        assert_eq!(trie.hash(), trie2.hash());
    }
    assert!(trie.is_empty());

    Ok(())
}

#[cfg(feature = "host")]
#[test]
fn test_serde_index_trie() -> Result<(), Error> {
    const N: usize = 512;

    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    for i in 0..N {
        assert!(trie.insert_rlp(&i.to_rlp(), i)?);
    }

    let root_hash = trie.hash();

    let encoded = trie.encode_trie();

    let recovered_trie = Mpt::decode_trie(&bump, &mut encoded.as_slice(), trie.num_nodes())?;
    assert_eq!(recovered_trie.hash(), root_hash);

    for i in 0..N {
        let value = recovered_trie.get_rlp(&i.to_rlp())?;
        assert_eq!(value, Some(i));
    }

    Ok(())
}

#[cfg(feature = "host")]
#[test]
fn test_serde_keccak_trie() -> Result<(), Error> {
    const N: usize = 512;

    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    for i in 0..N {
        assert!(trie.insert_rlp(keccak256(i.to_be_bytes()).as_slice(), i)?);
    }

    let root_hash = trie.hash();

    let encoded = trie.encode_trie();

    let recovered_trie = Mpt::decode_trie(&bump, &mut encoded.as_slice(), trie.num_nodes())?;
    assert_eq!(recovered_trie.hash(), root_hash);

    for i in 0..N {
        let value = recovered_trie.get_rlp(keccak256(i.to_be_bytes()).as_slice())?;
        assert_eq!(value, Some(i));
    }

    Ok(())
}

#[cfg(feature = "host")]
#[test]
fn test_serde_digest_root() -> Result<(), Error> {
    let bump = bumpalo::Bump::new();
    let digest = bump.alloc_slice_copy(&[0xabu8; 32]);
    let mut trie = Mpt::new(&bump);
    let root_id = trie.add_node(NodeData::Digest(digest), None);
    trie.set_root_id(root_id);

    let encoded = trie.encode_trie();
    let mut encoded_slice = encoded.as_slice();
    let recovered_trie = Mpt::decode_trie(&bump, &mut encoded_slice, trie.num_nodes())?;

    assert!(encoded_slice.is_empty());
    assert_eq!(recovered_trie.hash(), B256::from_slice(digest));
    Ok(())
}

/// Test that deleting a key that would cause branch collapse fails if sibling is unresolved Digest.
/// This tests the soundness fix: we must not assume an unresolved Digest is a Branch node.
#[test]
fn test_delete_with_unresolved_sibling_errors() {
    use crate::hp::to_encoded_path_with_bump;

    let bump = bumpalo::Bump::new();
    let mut trie = Mpt::new(&bump);

    // Create a fake 32-byte digest (simulating hash of an unknown node)
    let fake_digest: &[u8] = bump.alloc_slice_copy(&[0xABu8; 32]);

    // Build structure: Branch -> [Leaf at index 0, Digest at index 1]
    // When we delete the Leaf, the Branch should collapse, but we don't know
    // what the Digest represents, so we should error.
    //
    // Key 0x00 = nibbles [0, 0]:
    //   - First nibble 0 goes to branch child index 0 (the leaf)
    //   - Remaining nibble [0] must match leaf's path
    // So leaf path should be nibble [0].

    // Create a leaf node for index 0 with path [0] (to match second nibble of key 0x00)
    let leaf_path = to_encoded_path_with_bump(&bump, &[0], true);
    let leaf_id = trie.add_node(NodeData::Leaf(leaf_path, b"value"), None);

    // Create a digest node for index 1 (simulating unresolved sibling)
    let digest_id = trie.add_node(NodeData::Digest(fake_digest), None);

    // Create a branch with these two children
    let mut children: [Option<BranchChildId>; 16] = Default::default();
    children[0] = BranchChildId::new(leaf_id);
    children[1] = BranchChildId::new(digest_id);
    let branch_children = trie.alloc_branch(children);
    let branch_node_id = trie.add_node(NodeData::Branch(branch_children), None);

    // Set the root to the branch
    trie.set_root_id(branch_node_id);

    // Now try to delete the key 0x00 (nibbles [0, 0])
    // This should:
    //   1. Go to branch child 0 (the leaf)
    //   2. Match leaf path [0] with remaining nibbles [0]
    //   3. Delete the leaf
    //   4. Trigger branch collapse since only one child (digest at index 1) remains
    //   5. Fail because we don't know what the Digest represents
    let result = trie.delete(&[0x00]);

    // Should return NodeNotResolved error
    match result {
        Err(Error::NodeNotResolved(hash)) => {
            assert_eq!(hash, B256::from_slice(fake_digest));
        }
        Ok(_) => panic!("Expected NodeNotResolved error, but delete succeeded"),
        Err(e) => panic!("Expected NodeNotResolved error, got: {e:?}"),
    }
}
