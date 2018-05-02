extern crate rust_pbc;

pub mod boldyreva;
pub mod gdh;

#[cfg(test)]
mod gdh_tests {

    use gdh::{dealer, Share};
    use rust_pbc::{Curve, Element, Group, Pairing};
    use std::collections::HashMap;

    #[test]
    fn test_gdh() {
        let pairing = Pairing::new(Curve::SS512);

        let mut g1 = Element::new(Group::G1, &pairing);
        g1.set_from_hash("generate_g1".as_bytes().to_owned());

        let mut g2 = Element::new(Group::G1, &pairing);
        g2.set(&g1);

        let (public_key, secret_keys) = dealer(&pairing, &g1, &g2, 100, 35);

        let m = vec![1u8; 32];
        let c = public_key.encrypt(&pairing, &g1, m.clone());
        assert!(public_key.verify_ciphertext(&pairing, &g1, &c));

        let mut valid_shares: HashMap<u32, Share> = HashMap::new();
        let mut i = 0;
        for mut secret_key in secret_keys {
            let share = secret_key.decrypt_share(&pairing, &c);
            assert!(public_key.verify_share(&pairing, &g2, i.clone(), &share, &c));
            valid_shares.insert(i.clone() as u32, share);
            i += 1;
        }

        let valid_shares: HashMap<u32, Share> =
            valid_shares.drain().take(public_key.k as usize).collect();

        let r = public_key.combine_shares(&pairing, &c, &valid_shares);

        assert_eq!(m.clone(), r.clone());
    }

}

#[cfg(test)]
mod boldyreva_tests {

    use boldyreva::{dealer, Signature};
    use rust_pbc::{Curve, Element, Group, Pairing};
    use std::collections::HashMap;

    #[test]
    fn test_boldyreva() {
        let pairing = Pairing::new(Curve::MNT224);

        let mut g2 = Element::new(Group::G2, &pairing);
        g2.set_from_hash("generate_g2".as_bytes().to_owned());

        let (public_key, secret_keys) = dealer(&pairing, &g2, 64, 17);

        let h = public_key.hash_message(&pairing, vec![0u8; 32]);

        let mut sigs: HashMap<u32, Signature> = HashMap::new();
        for mut secret_key in secret_keys {
            sigs.insert(secret_key.i.clone(), secret_key.sign(&pairing, &h));
        }

        let sigs: HashMap<u32, Signature> = sigs.drain().take(public_key.k as usize).collect();

        let sig = public_key.combine_shares(&pairing, &sigs);

        assert!(public_key.verify_signature(&pairing, &g2, &sig, &h));
    }

}
