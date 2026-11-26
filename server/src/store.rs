//! Message store: one append-only canonical record stream per chat.
//! The phone keeps byte-identical copies of these streams, which is what makes
//! them usable as a shared compression dictionary.
//!
//! data/chats/<idx>.bin   canonical record stream of chat <idx>
//! data/meta.bin          chat JIDs, names and per-chat sender JIDs
//! data/media/<seq>.pb    kind byte ‖ protobuf of the WhatsApp media sub-message
//! data/dicts/<id>.bin    dictionaries trained during Sync

use crate::wire::*;
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Chat {
    pub jid: String,
    pub name: String,
    pub stream: Vec<u8>,
    /// (seq, byte offset, is_msg) for every record.
    pub index: Vec<(u64, usize, bool)>,
    pub pos: ChatPos,
    /// Sender JIDs; position i is per-chat sender index i + 1.
    pub senders: Vec<String>,
}

impl Chat {
    /// SERVICE_SIGNAL or SERVICE_WHATSAPP, from the chat id.
    pub fn service(&self) -> u8 {
        if crate::sig::is_signal(&self.jid) { SERVICE_SIGNAL } else { SERVICE_WHATSAPP }
    }

    pub fn last_seq(&self) -> u64 {
        self.pos.seq
    }

    /// Byte offset just after the record with `seq` (0 = start of stream).
    /// None if `seq` is not a record boundary of this chat.
    pub fn offset_after(&self, seq: u64) -> Option<usize> {
        if seq == 0 {
            return Some(0);
        }
        let i = self.index.binary_search_by_key(&seq, |e| e.0).ok()?;
        Some(self.index.get(i + 1).map_or(self.stream.len(), |e| e.1))
    }

    /// Index position of the first record with seq > `seq`.
    pub fn first_after(&self, seq: u64) -> usize {
        self.index.partition_point(|e| e.0 <= seq)
    }

    pub fn new_msgs_since(&self, seq: u64) -> usize {
        self.index[self.first_after(seq)..].iter().filter(|e| e.2).count()
    }
}

pub struct Store {
    dir: PathBuf,
    pub chats: Vec<Chat>,
    by_jid: HashMap<String, usize>,
    pub head: u64,
    pub dicts: Vec<Vec<u8>>, // dict id = position + 1; id 0 = empty
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        for d in ["chats", "media", "dicts"] {
            fs::create_dir_all(dir.join(d))?;
        }
        let mut s = Store { dir: dir.to_owned(), chats: vec![], by_jid: HashMap::new(), head: 0, dicts: vec![] };
        if let Ok(meta) = fs::read(dir.join("meta.bin")) {
            let mut b = &meta[..];
            let n = get_uv(&mut b)?;
            for idx in 0..n as usize {
                let jid = get_str(&mut b)?;
                let name = get_str(&mut b)?;
                let ns = get_uv(&mut b)?;
                let senders = (0..ns).map(|_| get_str(&mut b)).collect::<Result<Vec<_>>>()?;
                let stream = fs::read(dir.join(format!("chats/{idx}.bin"))).unwrap_or_default();
                let (pos, index) = ChatPos::scan(&stream)?;
                if pos.senders as usize > senders.len() {
                    bail!("chat {idx}: stream has more senders than meta");
                }
                s.head = s.head.max(pos.seq);
                s.by_jid.insert(jid.clone(), idx);
                s.chats.push(Chat { jid, name, stream, index, pos, senders });
            }
        }
        let mut id = 1;
        while let Ok(d) = fs::read(dir.join(format!("dicts/{id}.bin"))) {
            s.dicts.push(d);
            id += 1;
        }
        Ok(s)
    }

    fn save_meta(&self) -> Result<()> {
        let mut b = Vec::new();
        put_uv(&mut b, self.chats.len() as u64);
        for c in &self.chats {
            put_bytes(&mut b, c.jid.as_bytes());
            put_bytes(&mut b, c.name.as_bytes());
            put_uv(&mut b, c.senders.len() as u64);
            for s in &c.senders {
                put_bytes(&mut b, s.as_bytes());
            }
        }
        let tmp = self.dir.join("meta.bin.tmp");
        fs::write(&tmp, &b)?;
        fs::rename(tmp, self.dir.join("meta.bin"))?;
        Ok(())
    }

    pub fn chat_for(&mut self, jid: &str, name: &str) -> Result<usize> {
        if let Some(&i) = self.by_jid.get(jid) {
            return Ok(i);
        }
        let idx = self.chats.len();
        self.chats.push(Chat {
            jid: jid.to_owned(),
            name: name.to_owned(),
            stream: vec![],
            index: vec![],
            pos: ChatPos::default(),
            senders: vec![],
        });
        self.by_jid.insert(jid.to_owned(), idx);
        self.save_meta()?;
        Ok(idx)
    }

    fn append(&mut self, chat: usize, r: Record) -> Result<()> {
        let c = &mut self.chats[chat];
        let off = c.stream.len();
        let mut bytes = Vec::new();
        c.pos.encode(&r, &mut bytes);
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(format!("chats/{chat}.bin")))?
            .write_all(&bytes)?;
        c.stream.extend_from_slice(&bytes);
        c.index.push((r.seq(), off, matches!(r, Record::Msg { .. })));
        self.head = r.seq();
        Ok(())
    }

    /// Per-chat sender index for `jid` (never 0), defining it if new.
    pub fn sender_for(&mut self, chat: usize, jid: &str, name: &str) -> Result<u64> {
        if let Some(i) = self.chats[chat].senders.iter().position(|s| s == jid) {
            return Ok(i as u64 + 1);
        }
        self.chats[chat].senders.push(jid.to_owned());
        self.save_meta()?;
        let seq = self.head + 1;
        self.append(chat, Record::Sender { seq, name: name.to_owned() })?;
        Ok(self.chats[chat].senders.len() as u64)
    }

    /// Appends a message; returns (seq, previous seq in that chat).
    pub fn append_msg(&mut self, chat: usize, sender: u64, ts: i64, kind: u8, text: &str, media_size: u64) -> Result<(u64, u64)> {
        let prev = self.chats[chat].last_seq();
        let seq = self.head + 1;
        self.append(chat, Record::Msg { seq, sender, ts, kind, text: text.to_owned(), media_size })?;
        Ok((seq, prev))
    }

    /// Chats with messages newer than `since`: (chat idx, count).
    pub fn summary(&self, since: u64) -> Vec<(usize, usize)> {
        self.chats
            .iter()
            .enumerate()
            .filter(|(_, c)| c.last_seq() > since)
            .map(|(i, c)| (i, c.new_msgs_since(since)))
            .filter(|&(_, n)| n > 0)
            .collect()
    }

    /// Canonical chat-name table of the first `n` chats (SUMMARY dictionary).
    pub fn names_table(&self, n: usize) -> Vec<u8> {
        let mut b = Vec::new();
        for c in self.chats.iter().take(n) {
            put_bytes(&mut b, c.name.as_bytes());
        }
        b
    }

    pub fn dict(&self, id: u64) -> Option<&[u8]> {
        match id {
            0 => Some(&[]),
            n => self.dicts.get(n as usize - 1).map(|d| &d[..]),
        }
    }

    pub fn dict_id(&self) -> u64 {
        self.dicts.len() as u64
    }

    pub fn add_dict(&mut self, d: Vec<u8>) -> Result<u64> {
        let id = self.dicts.len() as u64 + 1;
        fs::write(self.dir.join(format!("dicts/{id}.bin")), &d)?;
        self.dicts.push(d);
        Ok(id)
    }

    pub fn media_path(&self, name: &str) -> PathBuf {
        self.dir.join("media").join(name)
    }

    pub fn save_media_ref(&self, seq: u64, kind: u8, proto: &[u8]) -> Result<()> {
        let mut b = vec![kind];
        b.extend_from_slice(proto);
        fs::write(self.media_path(&format!("{seq}.pb")), b)?;
        Ok(())
    }

    pub fn load_media_ref(&self, seq: u64) -> Option<(u8, Vec<u8>)> {
        let b = fs::read(self.media_path(&format!("{seq}.pb"))).ok()?;
        let (&kind, rest) = b.split_first()?;
        Some((kind, rest.to_vec()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("svpn-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn persist_and_reload() {
        let dir = tmpdir("store");
        {
            let mut s = Store::open(&dir).unwrap();
            let a = s.chat_for("alex@s.whatsapp.net", "Alex").unwrap();
            let g = s.chat_for("grp@g.us", "Group").unwrap();
            let sa = s.sender_for(a, "alex@s.whatsapp.net", "Alex").unwrap();
            assert_eq!(sa, 1);
            s.append_msg(a, sa, 100, KIND_TEXT, "hi", 0).unwrap();
            let sb = s.sender_for(g, "bob@s.whatsapp.net", "Bob").unwrap();
            s.append_msg(g, sb, 101, KIND_IMAGE, "pic", 1234).unwrap();
            let (seq, prev) = s.append_msg(a, 0, 102, KIND_TEXT, "hello", 0).unwrap();
            assert_eq!((seq, prev), (5, 2));
            s.add_dict(b"dict".to_vec()).unwrap();
        }
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.head, 5);
        assert_eq!(s.chats.len(), 2);
        assert_eq!(s.chats[0].senders, vec!["alex@s.whatsapp.net"]);
        assert_eq!(s.summary(0), vec![(0, 2), (1, 1)]);
        assert_eq!(s.summary(4), vec![(0, 1)]);
        assert_eq!(s.chats[0].offset_after(2), Some(s.chats[0].index[2].1));
        assert_eq!(s.chats[0].offset_after(3), None);
        assert_eq!(s.dict(1), Some(&b"dict"[..]));
        assert_eq!(s.dict_id(), 1);
    }
}
