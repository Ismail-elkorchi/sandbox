//! Guest-service concurrency coordination, not a host security boundary.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
pub struct ConnectionBudget {
    current: Arc<AtomicUsize>,
    maximum: usize,
}

pub struct ConnectionLease(Arc<AtomicUsize>);

impl ConnectionBudget {
    pub fn new(maximum: usize) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            maximum,
        }
    }

    pub fn try_acquire(&self) -> Option<ConnectionLease> {
        let mut current = self.current.load(Ordering::Acquire);
        while current < self.maximum {
            match self.current.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnectionLease(Arc::clone(&self.current))),
                Err(observed) => current = observed,
            }
        }
        None
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rejected_or_completed_connection_releases_its_slot() {
        let budget = ConnectionBudget::new(2);
        let first = budget.try_acquire().unwrap();
        let second = budget.clone().try_acquire().unwrap();
        assert!(budget.try_acquire().is_none());
        drop(first);
        let replacement = budget.try_acquire().unwrap();
        drop(second);
        drop(replacement);
        assert_eq!(budget.current.load(Ordering::Acquire), 0);
    }

    #[test]
    fn concurrent_admission_never_exceeds_capacity() {
        let budget = ConnectionBudget::new(1);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        if let Some(_lease) = budget.try_acquire() {
                            assert_eq!(budget.current.load(Ordering::Acquire), 1);
                            std::thread::yield_now();
                        }
                    }
                });
            }
        });
        assert_eq!(budget.current.load(Ordering::Acquire), 0);
    }
}
