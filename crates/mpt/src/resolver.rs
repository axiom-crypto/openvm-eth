use crate::{
    node::{BranchChildId, NodeData, NodeId},
    trie::{NULL_NODE_ID, NULL_NODE_REF_SLICE},
    Error, Mpt,
};
use alloy_rlp::PayloadView;
use bumpalo::Bump;
use bytes::{BufMut, BytesMut};
use revm_primitives::{Bytes, HashMap, B256};

/// [`MptResolver`] resolves an MPT from a from a given mapping of `keccak(payload) -> payload` of
/// all MPT nodes.
#[derive(Debug)]
pub struct MptResolver {
    node_store: HashMap<B256, Bytes>,
}

impl FromIterator<(B256, Bytes)> for MptResolver {
    fn from_iter<T: IntoIterator<Item = (B256, Bytes)>>(iter: T) -> Self {
        Self { node_store: HashMap::from_iter(iter) }
    }
}

impl MptResolver {
    pub fn new(node_store: HashMap<B256, Bytes>) -> Self {
        MptResolver { node_store }
    }

    /// Resolves an MPT from the mapping stored in [`MptResolver`] given its `root` hash. All node
    /// data is copied into `bump`.
    pub fn resolve<'a>(&self, bump: &'a Bump, root: &B256) -> Result<Mpt<'a>, Error> {
        let mut mpt = Mpt::new(bump);

        let rlp_root = {
            let mut out = BytesMut::with_capacity(33);
            out.put_u8(alloy_rlp::EMPTY_STRING_CODE + 32);
            out.put_slice(root.as_slice());
            out.to_vec()
        };

        let root_id = self.resolve_internal(&mut rlp_root.as_slice(), &mut mpt)?;
        mpt.set_root_id(root_id);

        Ok(mpt)
    }

    fn resolve_internal(&self, node_bytes: &mut &[u8], mpt: &mut Mpt<'_>) -> Result<NodeId, Error> {
        let node_id = match alloy_rlp::Header::decode_raw(node_bytes)? {
            PayloadView::String(item) => match item.len() {
                0 => NULL_NODE_ID,
                32 => match self.node_store.get(&B256::from_slice(item)) {
                    Some(resolved_node_bytes) => {
                        self.resolve_internal(&mut resolved_node_bytes.as_ref(), mpt)?
                    }
                    None => mpt.add_node_copied(&NodeData::Digest(item)),
                },
                _ => {
                    return Err(Error::RlpError(alloy_rlp::Error::UnexpectedLength));
                }
            },
            PayloadView::List(mut items) => match items.len() {
                2 => {
                    let path = alloy_rlp::Header::decode_bytes(&mut items[0], false)?;
                    let prefix = path[0];
                    if (prefix & (2 << 4)) == 0 {
                        let ext_node_id = self.resolve_internal(&mut items[1], mpt)?;
                        let node_data = NodeData::Extension(path, ext_node_id);
                        mpt.add_node_copied(&node_data)
                    } else {
                        let value = alloy_rlp::Header::decode_bytes(&mut items[1], false)?;
                        let node_data = NodeData::Leaf(path, value);
                        mpt.add_node_copied(&node_data)
                    }
                }
                17 => {
                    if items[16] != NULL_NODE_REF_SLICE {
                        return Err(Error::ValueInBranch);
                    }

                    let mut childs: [Option<BranchChildId>; 16] = Default::default();
                    for (i, mut item) in items.into_iter().take(16).enumerate() {
                        let child_id = self.resolve_internal(&mut item, mpt)?;
                        // `BranchChildId::new` maps the `NULL_NODE_ID` sentinel (0) to `None`.
                        childs[i] = BranchChildId::new(child_id);
                    }
                    // The children array is allocated in `mpt`'s own bump, so no copy is needed.
                    let children = mpt.alloc_branch(childs);
                    mpt.add_node(NodeData::Branch(children), None)
                }
                _ => {
                    return Err(Error::RlpError(alloy_rlp::Error::UnexpectedLength));
                }
            },
        };
        Ok(node_id)
    }
}

#[cfg(test)]
mod tests {
    use revm_primitives::{keccak256, map::DefaultHashBuilder, HashMap};

    use crate::{resolver::MptResolver, Error, Mpt};

    #[test]
    fn test_resolve_keccak_trie() -> Result<(), Error> {
        const N: usize = 512;

        let bump = bumpalo::Bump::new();
        let mut trie = Mpt::new(&bump);

        for i in 0..N {
            assert!(trie.insert_rlp(keccak256(i.to_be_bytes()).as_slice(), i)?);
        }

        let payloads = trie.payloads();
        let mut node_store =
            HashMap::with_capacity_and_hasher(payloads.len(), DefaultHashBuilder::default());
        for payload in payloads {
            node_store.insert(keccak256(&payload), payload);
        }

        let mpt_resolver = MptResolver::from_iter(node_store);
        let resolve_bump = bumpalo::Bump::new();
        let resolved_trie = mpt_resolver.resolve(&resolve_bump, &trie.hash())?;

        assert_eq!(resolved_trie.hash(), trie.hash());

        Ok(())
    }
}
