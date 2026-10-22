use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Default)]
pub struct FillRegistry(Arc<Mutex<HashMap<String, watch::Sender<bool>>>>);
pub struct FillGuard {
    registry: FillRegistry,
    key: String,
    sender: watch::Sender<bool>,
}
pub enum FillClaim {
    Leader(FillGuard),
    Follower(watch::Receiver<bool>),
    Saturated,
}
impl FillRegistry {
    pub fn cancel_all(&self) {
        let mut entries = self.0.lock().unwrap();
        for (_, sender) in entries.drain() {
            let _ = sender.send(true);
        }
    }
    pub fn claim(&self, key: &str) -> FillClaim {
        let mut entries = self.0.lock().unwrap();
        if let Some(sender) = entries.get(key) {
            return FillClaim::Follower(sender.subscribe());
        }
        if entries.len() >= 256 {
            return FillClaim::Saturated;
        }
        let (sender, _) = watch::channel(false);
        entries.insert(key.to_owned(), sender.clone());
        FillClaim::Leader(FillGuard {
            registry: self.clone(),
            key: key.to_owned(),
            sender,
        })
    }
}
impl Drop for FillGuard {
    fn drop(&mut self) {
        let mut entries = self.registry.0.lock().unwrap();
        if entries
            .get(&self.key)
            .is_some_and(|sender| sender.same_channel(&self.sender))
        {
            entries.remove(&self.key);
        }
        let _ = self.sender.send(true);
    }
}
