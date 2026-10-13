//! Scheduling helpers for the parallel hunt. Pure logic (unit-tested on Linux).
//!
//! The per-process memory and YARA phases are embarrassingly parallel, but process cost spans
//! three orders of magnitude: a desktop may hold `chrome.exe` with 300 threads next to
//! `fontdrvhost.exe` with 2. If workers pick from a FIFO list, one of them ends up alone with
//! the biggest process at the tail. We sort by a weight proportional to expected scan cost so
//! the heaviest items start first, and let the small tail finish together across all workers.

/// Return the indices of `items` in a "largest cost first" order. Stable for equal weights so
/// the order of same-cost processes is predictable in reports.
pub fn heavy_first<T>(items: &[T], weight: impl Fn(&T) -> u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..items.len()).collect();
    idx.sort_by(|&a, &b| weight(&items[b]).cmp(&weight(&items[a])).then(a.cmp(&b)));
    idx
}

/// How many worker threads to use for `n` items given a requested count. Capped above by `max`
/// (process limit), and below by 1. Never more workers than items (idle threads waste a stack).
pub fn worker_count(items: usize, requested: Option<usize>, max: usize) -> usize {
    if items == 0 {
        return 1;
    }
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    requested.unwrap_or(cpus).clamp(1, max.min(items).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn largest_first_breaks_ties_stably() {
        let v = vec![10u64, 100, 10, 50, 100];
        let order = heavy_first(&v, |x| *x);
        assert_eq!(order, vec![1, 4, 3, 0, 2]);
    }

    #[test]
    fn empty_input_is_safe() {
        let empty: Vec<u64> = Vec::new();
        assert!(heavy_first(&empty, |x| *x).is_empty());
        assert_eq!(worker_count(0, Some(8), 16), 1);
    }

    #[test]
    fn workers_bounded_by_items_and_max() {
        assert_eq!(worker_count(3, Some(8), 16), 3);
        assert_eq!(worker_count(100, Some(0), 16), 1);
        assert_eq!(worker_count(100, Some(999), 16), 16);
    }
}
