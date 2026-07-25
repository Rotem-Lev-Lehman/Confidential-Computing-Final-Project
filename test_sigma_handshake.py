"""
test_sigma_handshake.py
=======================
Tests for the signature-based SIGMA handshake (per-node Ed25519 identities).

Run with:  python3 test_sigma_handshake.py
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sigma_handshake as sig
from sigma_handshake import HandshakeError, generate_identity_keypair, load_public_key


def make_identities(node_ids):
    """Build {id: signing_key} and {id: public_key} for a set of nodes."""
    signing, public = {}, {}
    for nid in node_ids:
        priv_raw, pub_raw = generate_identity_keypair()
        signing[nid] = Ed25519PrivateKey.from_private_bytes(priv_raw)
        public[nid] = load_public_key(pub_raw.hex())
    return signing, public


def run_handshake(initiator, responder, signing, public,
                  initiator_signing=None, claimed_initiator=None):
    """Run the 3-message handshake; returns (key_i, key_r, authenticated_id)."""
    st_i, msg1 = sig.initiator_start(claimed_initiator or initiator)
    st_r, msg2 = sig.responder_handle_msg1(msg1, responder, signing[responder])
    key_i, msg3 = sig.initiator_handle_msg2(
        msg2, st_i, responder, public[responder],
        initiator_signing or signing[initiator],
    )
    key_r, who = sig.responder_handle_msg3(msg3, st_r, public)
    return key_i, key_r, who


def test_both_sides_agree():
    signing, public = make_identities([1, 2])
    key_i, key_r, who = run_handshake(1, 2, signing, public)
    assert key_i == key_r, "session keys differ"
    assert len(key_i) == 32, f"expected 32-byte key, got {len(key_i)}"
    assert who == 1, f"authenticated wrong node: {who}"
    print("PASS: test_both_sides_agree")


def test_fresh_key_each_session():
    """Ephemeral DH -> a new session key every handshake (forward secrecy)."""
    signing, public = make_identities([1, 2])
    k1, _, _ = run_handshake(1, 2, signing, public)
    k2, _, _ = run_handshake(1, 2, signing, public)
    assert k1 != k2, "two handshakes produced the same key -- not ephemeral"
    print("PASS: test_fresh_key_each_session")


def test_impersonation_rejected():
    """Node 3 cannot pose as node 1: it lacks node 1's private key.

    This is the property a single shared PSK could NOT provide -- with a group
    PSK, any member could impersonate any other.
    """
    signing, public = make_identities([1, 2, 3])
    try:
        # Node 3 signs, but claims to be node 1.
        run_handshake(1, 2, signing, public,
                      initiator_signing=signing[3], claimed_initiator=1)
        assert False, "expected HandshakeError, impersonation succeeded"
    except HandshakeError as exc:
        assert "signature invalid" in str(exc), str(exc)
    print("PASS: test_impersonation_rejected")


def test_wrong_peer_identity_rejected():
    """Dialling node 2 but reaching node 3 must abort."""
    signing, public = make_identities([1, 2, 3])
    st_i, msg1 = sig.initiator_start(1)
    # Node 3 answers instead of node 2.
    _, msg2 = sig.responder_handle_msg1(msg1, 3, signing[3])
    try:
        sig.initiator_handle_msg2(msg2, st_i, 2, public[2], signing[1])
        assert False, "expected HandshakeError for wrong peer"
    except HandshakeError as exc:
        assert "claims to be" in str(exc), str(exc)
    print("PASS: test_wrong_peer_identity_rejected")


def test_tampered_dh_key_rejected():
    """Swapping g_b in transit breaks the responder's signature."""
    signing, public = make_identities([1, 2])
    st_i, msg1 = sig.initiator_start(1)
    _, msg2 = sig.responder_handle_msg1(msg1, 2, signing[2])
    _, evil_g = sig.generate_ephemeral_keypair()
    msg2_tampered = {**msg2, "g": evil_g.hex()}
    try:
        sig.initiator_handle_msg2(msg2_tampered, st_i, 2, public[2], signing[1])
        assert False, "expected HandshakeError for tampered DH key"
    except HandshakeError as exc:
        assert "signature invalid" in str(exc), str(exc)
    print("PASS: test_tampered_dh_key_rejected")


def test_replayed_msg2_rejected():
    """A msg2 recorded from an earlier session fails against a fresh transcript."""
    signing, public = make_identities([1, 2])
    st_old, msg1_old = sig.initiator_start(1)
    _, msg2_old = sig.responder_handle_msg1(msg1_old, 2, signing[2])

    st_new, _ = sig.initiator_start(1)          # new session, new g_a
    try:
        sig.initiator_handle_msg2(msg2_old, st_new, 2, public[2], signing[1])
        assert False, "expected HandshakeError on replayed msg2"
    except HandshakeError:
        print("PASS: test_replayed_msg2_rejected")


def test_identity_change_mid_handshake_rejected():
    """The id in msg3 must match the one claimed in msg1."""
    signing, public = make_identities([1, 2, 3])
    st_i, msg1 = sig.initiator_start(1)
    st_r, msg2 = sig.responder_handle_msg1(msg1, 2, signing[2])
    _, msg3 = sig.initiator_handle_msg2(msg2, st_i, 2, public[2], signing[1])
    msg3_swapped = {**msg3, "from": 3}          # claim a different id late
    try:
        sig.responder_handle_msg3(msg3_swapped, st_r, public)
        assert False, "expected HandshakeError on identity change"
    except HandshakeError as exc:
        assert "changed mid-handshake" in str(exc), str(exc)
    print("PASS: test_identity_change_mid_handshake_rejected")


def test_unknown_node_rejected():
    """A node with no configured public key cannot authenticate."""
    signing, public = make_identities([1, 2])
    stranger, _ = make_identities([9])
    st_i, msg1 = sig.initiator_start(9)
    st_r, msg2 = sig.responder_handle_msg1(msg1, 2, signing[2])
    _, msg3 = sig.initiator_handle_msg2(msg2, st_i, 2, public[2], stranger[9])
    try:
        sig.responder_handle_msg3(msg3, st_r, public)   # no key for node 9
        assert False, "expected HandshakeError for unknown node"
    except HandshakeError as exc:
        assert "no public key" in str(exc), str(exc)
    print("PASS: test_unknown_node_rejected")


def test_no_shared_secret_anywhere():
    """Each node's signing key is distinct -- there is no group secret."""
    signing, _ = make_identities([1, 2, 3, 4])
    raws = {nid: k.private_bytes_raw() for nid, k in signing.items()}
    assert len(set(raws.values())) == 4, "signing keys are not distinct"
    print("PASS: test_no_shared_secret_anywhere")


if __name__ == "__main__":
    test_both_sides_agree()
    test_fresh_key_each_session()
    test_impersonation_rejected()
    test_wrong_peer_identity_rejected()
    test_tampered_dh_key_rejected()
    test_replayed_msg2_rejected()
    test_identity_change_mid_handshake_rejected()
    test_unknown_node_rejected()
    test_no_shared_secret_anywhere()
    print("\nAll SIGMA handshake tests passed.")
