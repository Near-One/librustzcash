use blake2b_simd::Hash as Blake2bHash;

use ::transparent::{bundle as transparent, sighash::TransparentAuthorizingContext};

use crate::transaction::{
    Authorization, TransactionData, TxDigests, sighash::SignableInput,
    sighash_v5::transparent_sig_digest, txid::to_hash_v6,
};

pub fn v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the
    // transaction has a transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash_v6(
        tx.consensus_branch_id,
        txid_parts.header_digest,
        transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.ironwood_digest,
    )
}

/// V6 counterpart of [`my_signature_hash`]: computes the signature hash using
/// an externally supplied transparent bundle that carries the authorizing
/// context (input amounts and script pubkeys), which the transparent bundle of
/// an extracted transaction does not provide.
///
/// [`my_signature_hash`]: crate::transaction::sighash_v5::my_signature_hash
pub fn my_signature_hash_v6<A: Authorization, TA: TransparentAuthorizingContext>(
    tx: &TransactionData<A>,
    transp_bundel: Option<transparent::Bundle<TA>>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the
    // transaction has a transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash_v6(
        tx.consensus_branch_id,
        txid_parts.header_digest,
        transparent_sig_digest(
            transp_bundel
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.ironwood_digest,
    )
}
