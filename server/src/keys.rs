//! Server-side key state: the current key plus (right after a Sync rotation)
//! the previous key until the phone proves it has the new one.
//! Persisted to data/keys.bin after every change, so restarts never reuse a nonce.

use crate::wire::*;
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};

/// Packet numbers are reserved on disk in blocks of this size.
const TX_BLOCK: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub key: [u8; 32],
    pub tx_next: u64,
    pub tx_reserved: u64,
    pub rx: RxWindow,
}

impl Slot {
    pub fn new(key: [u8; 32]) -> Slot {
        Slot { key, tx_next: 0, tx_reserved: 0, rx: RxWindow::default() }
    }
}

pub struct Keys {
    path: PathBuf,
    /// slots[0] is the newest key.
    pub slots: Vec<Slot>,
}

pub fn derive_rotated(old: &[u8; 32], dh: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(old), dh).expand(b"svpn-rotate", &mut out).expect("hkdf");
    out
}

impl Keys {
    pub fn create(path: &Path, key: [u8; 32]) -> Result<Keys> {
        let k = Keys { path: path.to_owned(), slots: vec![Slot::new(key)] };
        k.save()?;
        Ok(k)
    }

    pub fn load(path: &Path) -> Result<Keys> {
        let b = fs::read(path)?;
        let mut s = &b[..];
        let n = get_uv(&mut s)?;
        let mut slots = Vec::new();
        for _ in 0..n {
            let key: [u8; 32] = get_bytes(&mut s)?.try_into()?;
            let tx_reserved = get_uv(&mut s)?;
            let next = get_uv(&mut s)?;
            let bitmap = get_uv(&mut s)?;
            // After a restart, continue from the reserved block boundary.
            slots.push(Slot { key, tx_next: tx_reserved, tx_reserved, rx: RxWindow { next, bitmap } });
        }
        Ok(Keys { path: path.to_owned(), slots })
    }

    pub fn save(&self) -> Result<()> {
        let mut b = Vec::new();
        put_uv(&mut b, self.slots.len() as u64);
        for s in &self.slots {
            put_bytes(&mut b, &s.key);
            put_uv(&mut b, s.tx_reserved);
            put_uv(&mut b, s.rx.next);
            put_uv(&mut b, s.rx.bitmap);
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, &b)?;
        fs::File::open(&tmp)?.sync_all()?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }

    /// Decrypts a phone packet. Returns (slot index, plaintext).
    /// A packet under the newest key retires all older keys.
    pub fn open(&mut self, pkt: &[u8]) -> Option<(usize, Vec<u8>)> {
        let (i, pn, pt) = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(i, s)| s.rx.open(&s.key, DIR_C2S, pkt).map(|(pn, pt)| (i, pn, pt)))?;
        self.slots[i].rx.accept(pn);
        if i == 0 {
            self.slots.truncate(1);
        }
        if let Err(e) = self.save() {
            log::error!("saving keys: {e}");
        }
        Some((i, pt))
    }

    /// Encrypts a reply under the key of `slot`.
    pub fn seal(&mut self, slot: usize, plaintext: &[u8]) -> Vec<u8> {
        let i = slot.min(self.slots.len() - 1);
        let s = &mut self.slots[i];
        if s.tx_next >= s.tx_reserved {
            s.tx_reserved = s.tx_next + TX_BLOCK;
            if let Err(e) = self.save() {
                log::error!("saving keys: {e}");
            }
        }
        let s = &mut self.slots[i];
        let pn = s.tx_next;
        s.tx_next += 1;
        seal(&s.key, DIR_S2C, pn, plaintext)
    }

    /// Rotates from the key in `slot` using a fresh DH secret. The new key
    /// becomes slots[0]; the old one is kept until the phone uses the new one.
    pub fn rotate(&mut self, slot: usize, dh: &[u8; 32]) -> Result<()> {
        let old = self.slots[slot].clone();
        let new = Slot::new(derive_rotated(&old.key, dh));
        self.slots = vec![new, old];
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::tmpdir;

    #[test]
    fn restart_and_rotation() {
        let dir = tmpdir("keys");
        let path = dir.join("keys.bin");
        let k0 = [9u8; 32];
        let mut keys = Keys::create(&path, k0).unwrap();
        let p = seal(&k0, DIR_C2S, 0, b"a");
        assert_eq!(keys.open(&p).unwrap(), (0, b"a".to_vec()));
        let reply = keys.seal(0, b"r");
        assert_eq!(RxWindow::default().open(&k0, DIR_S2C, &reply).unwrap().0, 0);

        // restart: tx continues after the reserved block, rx replay state kept
        let mut keys = Keys::load(&path).unwrap();
        assert!(keys.open(&p).is_none(), "replay after restart");
        let reply = keys.seal(0, b"r2");
        let mut rx = RxWindow::default();
        rx.accept(0);
        assert_eq!(rx.open(&k0, DIR_S2C, &reply).unwrap().0, TX_BLOCK);

        // rotation: old key still accepted until the new one is used
        keys.rotate(0, &[1u8; 32]).unwrap();
        let k1 = derive_rotated(&k0, &[1u8; 32]);
        assert_eq!(keys.open(&seal(&k0, DIR_C2S, 1, b"old")).unwrap().0, 1);
        assert_eq!(keys.open(&seal(&k1, DIR_C2S, 0, b"new")).unwrap().0, 0);
        assert!(keys.open(&seal(&k0, DIR_C2S, 2, b"old")).is_none(), "old key retired");
        assert_eq!(keys.slots.len(), 1);
    }
}
