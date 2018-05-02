use rust_pbc::{lagrange, xor, Element, ElementPP, Group, Pairing};
use std::collections::HashMap;
use std::collections::HashSet;

use gdh::share::{EncryptedShare, Share};

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

    pub fn encrypt(&self, pairing: &Pairing, g1: &Element, m: Vec<u8>) -> EncryptedShare {
        assert_eq!(m.len(), 32); // Message length must be 32 bytes

        let mut pp = ElementPP::new();

        // r = rng(Zr)
        let mut r = Element::new(Group::Zr, pairing);
        r.random();

        // u = g1 ^ r
        let mut u = Element::new(Group::G1, pairing);
        pp.init(g1);
        pp.pow_zn(&mut u, &mut r);

        // h = vk ^ r
        let mut h = Element::new(Group::G1, pairing);
        pp.init(&self.vk);
        pp.pow_zn(&mut h, &mut r);

        // v = xor(m, H(vk ^ r))
        let h = h.hash_g();
        let v = xor(m.clone(), h);

        // w_init = hashH(u, v)
        let w_init = u.hash_h(pairing, v.clone());
        // w = w_init ^ r
        let mut w = Element::new(Group::G1, pairing);
        pp.init(&w_init);
        pp.pow_zn(&mut w, &mut r);

        // c = (u, v, w)
        EncryptedShare::new(u, v, w)
    }

    pub fn verify_ciphertext(&self, pairing: &Pairing, g1: &Element, uvw: &EncryptedShare) -> bool {
        let h = uvw.u.hash_h(pairing, uvw.v.clone());

        let p1 = g1.pair(pairing, &uvw.w);
        let p2 = uvw.u.pair(pairing, &h);

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
        i: i32,
        u_i: &Share,
        uvw: &EncryptedShare,
    ) -> bool {
        assert!((0 <= i.clone()) && (i.clone() < self.l.clone() as i32));

        let y_i = &self.vks[i.clone() as usize];

        let p1 = u_i.pair(pairing, g2);
        let p2 = uvw.u.pair(pairing, y_i);

        if p1.cmp(&p2) == 0 {
            true
        } else {
            false
        }
    }

    pub fn combine_shares(
        &self,
        pairing: &Pairing,
        uvw: &EncryptedShare,
        shares: &HashMap<u32, Share>,
    ) -> Vec<u8> {
        let mut s: HashSet<i64> = HashSet::new();
        for (j, _) in shares.iter() {
            s.insert(j.clone() as i64);
        }

        let expected_s: HashSet<i64> = (0..self.l).map(|i| i as i64).collect();

        assert!(s.is_subset(&expected_s));

        // Assumes self.verify_ciphertext(&uvw) == true
        let mut pp = ElementPP::new();

        let mut combined = Element::new(Group::G1, pairing);
        combined.set1();

        for (j, share) in shares.iter() {
            // share ^ lagrange(s, j)
            let mut l = lagrange(pairing, self.k, self.l, &s, j.clone() as i64);
            let mut r = Element::new(Group::G1, pairing);
            pp.init(&share);
            pp.pow_zn(&mut r, &mut l);
            combined.mul(&r);
        }

        xor(combined.hash_g(), uvw.v.clone())
    }
}
