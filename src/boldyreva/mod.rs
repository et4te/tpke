// Threshold encryption based on Alexandra Boldyrevas' scheme

pub mod private_key;
pub mod public_key;
pub mod signature;

pub use self::private_key::PrivateKey;
pub use self::public_key::PublicKey;
pub use self::signature::Signature;

use rust_pbc::{lagrange, polynomial, Element, ElementPP, Group, Pairing};
use std::collections::HashSet;

// Produces a public key and a series of private keys for signing a 32-byte message.
// The public key can be used to combine a set of signatures together and be used to
// verify the signatures independently. A threshold 'k' of signatures are required
// in order to reconstruct a legitimate signature.

pub fn dealer(
    pairing: &Pairing,
    g2: &Element,
    players: u32,
    k: u32,
) -> (PublicKey, Vec<PrivateKey>) {
    // Generate a random secret in Zr
    let mut secret = Element::new(Group::Zr, &pairing);
    secret.random();

    // Copy the secret for later re-use
    let mut secret_copy = Element::new(Group::Zr, &pairing);
    secret_copy.set(&secret);

    // Generate polynomial co-efficients
    let mut coefficients = vec![secret];
    for _ in 1..k {
        let mut r = Element::new(Group::Zr, &pairing);
        r.random();
        coefficients.push(r);
    }

    assert_eq!(coefficients.len(), k as usize);

    // Polynomial evaluation

    // secret_keys = [f(i) | i in (1..players+1)]
    let mut secret_keys = vec![];
    for i in 1..players + 1 {
        let mut x = Element::new(Group::Zr, &pairing);
        x.set_si(i as i64);
        let secret_key = polynomial(&x, &pairing, &coefficients);
        secret_keys.push(secret_key);
    }

    let mut zero = Element::new(Group::Zr, &pairing);
    zero.set0();

    let master_key = polynomial(&zero, &pairing, &coefficients);
    assert!(master_key.cmp(&secret_copy) == 0);
    // master_key.print("master_key = ".to_string());

    // Verification keys & Private keys

    let mut pp = ElementPP::new();

    let mut master_verification_key = Element::new(Group::G2, &pairing);

    // vk = g2 ^ secret_copy
    pp.init(&g2);
    pp.pow_zn(&mut master_verification_key, &mut secret_copy);

    let mut verification_keys = vec![];

    let mut i = 0;
    let mut private_keys: Vec<PrivateKey> = vec![];
    for mut secret_key in secret_keys {
        // collect verification keys
        let mut verification_key = Element::new(Group::G2, &pairing);
        pp.pow_zn(&mut verification_key, &mut secret_key);
        verification_keys.push(verification_key);

        // collect private keys
        let private_key = PrivateKey {
            l: players.clone(),
            k: k.clone(),
            sk: secret_key,
            i: i.clone(),
        };
        private_keys.push(private_key);

        i += 1;
    }

    // Encryption & Public key

    let public_key = PublicKey {
        l: players.clone(),
        k: k.clone(),
        vk: master_verification_key,
        vks: verification_keys,
    };

    // Check reconstruction of 0
    let lhs = polynomial(&zero, &pairing, &coefficients);
    assert!(lhs.cmp(&secret_copy) == 0);

    let mut s: HashSet<i64> = HashSet::new();
    for i in 0..k {
        s.insert(i.clone() as i64);
    }

    let mut rhs = Element::new(Group::Zr, &pairing);
    rhs.set0();

    for j in s.iter().clone() {
        // x = j + 1
        let mut x = Element::new(Group::Zr, &pairing);
        x.set_si(j.clone() + 1);
        // p = polynomial(x, pairing, coeffs)
        let p = polynomial(&x, &pairing, &coefficients);
        // l = lagrange(public_key, s, j)
        let mut l = lagrange(&pairing, public_key.k, public_key.l, &s, j.clone());
        // l = l * p
        l.mul(&p);
        // rhs += l
        rhs.add(&l);
    }

    assert!(lhs.cmp(&rhs) == 0);

    (public_key, private_keys)
}
