use rust_pbc::{lagrange, Element, ElementPP, Group, Pairing};
use std::collections::HashMap;
use std::collections::HashSet;

use boldyreva::signature::Signature;

pub struct PublicKey {
    pub l: u32,
    pub k: u32,
    pub vk: Element,
    pub vks: Vec<Element>,
}

impl PublicKey {
    pub fn new(l: u32, k: u32, vk: Element, vks: Vec<Element>) -> PublicKey {
        PublicKey {
            l: l,
            k: k,
            vk: vk,
            vks: vks,
        }
    }

    pub fn hash_message(&self, pairing: &Pairing, m: Vec<u8>) -> Element {
        let mut h = Element::new(Group::G1, pairing);
        h.set_from_hash(m.clone());
        h
    }

    pub fn verify_signature(
        &self,
        pairing: &Pairing,
        g2: &Element,
        sig: &Signature,
        h: &Element,
    ) -> bool {
        let p1 = sig.pair(pairing, g2);
        let p2 = h.pair(pairing, &self.vk);
        if p1.cmp(&p2) == 0 {
            true
        } else {
            false
        }
    }

    pub fn verify_share(
        &self,
        pairing: &Pairing,
        g2: &Element,
        sig: &Signature,
        i: i32,
        h: &Element,
    ) -> bool {
        assert!((0 <= i.clone()) && (i.clone() < self.l.clone() as i32));

        let b = &self.vks[i.clone() as usize];

        let p1 = sig.pair(pairing, g2);
        let p2 = h.pair(pairing, b);

        if p1.cmp(&p2) == 0 {
            true
        } else {
            false
        }
    }

    pub fn combine_shares(&self, pairing: &Pairing, sigs: &HashMap<u32, Signature>) -> Element {
        let mut s: HashSet<i64> = HashSet::new();
        for (j, _) in sigs.iter() {
            s.insert(j.clone() as i64);
        }

        let expected_s: HashSet<i64> = (0..self.l).map(|i| i as i64).collect();

        assert!(s.is_subset(&expected_s));

        // Assumes self.verify_ciphertext(&uvw) == true
        let mut pp = ElementPP::new();

        let mut combined = Element::new(Group::G1, pairing);
        combined.set1();

        for (j, sig) in sigs.iter() {
            // share ^ lagrange(s, j)
            let mut l = lagrange(pairing, self.k, self.l, &s, j.clone() as i64);
            let mut r = Element::new(Group::G1, pairing);
            pp.init(&sig);
            pp.pow_zn(&mut r, &mut l);
            combined.mul(&r);
        }

        combined
    }
}
