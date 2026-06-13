//! Tiny percentile helper. Takes a mutable slice (sorts in place) and
//! returns min / p50 / p95 / p99 / max. All values inclusive of the
//! endpoints. Input MUST be non-empty.

#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub n: usize,
    pub min: usize,
    pub p50: usize,
    pub p95: usize,
    pub p99: usize,
    pub max: usize,
}

impl Summary {
    pub fn from_slice(sizes: &mut [usize]) -> Option<Self> {
        if sizes.is_empty() {
            return None;
        }
        sizes.sort_unstable();
        let n = sizes.len();
        let pick = |q: f64| -> usize {
            // Nearest-rank definition — n * q, round up, clamp to len.
            let rank = ((q * n as f64).ceil() as usize).clamp(1, n);
            sizes[rank - 1]
        };
        Some(Self {
            n,
            min: sizes[0],
            p50: pick(0.50),
            p95: pick(0.95),
            p99: pick(0.99),
            max: sizes[n - 1],
        })
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n={} min={}B p50={}B p95={}B p99={}B max={}B",
            self.n, self.min, self.p50, self.p95, self.p99, self.max
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_element() {
        let mut sizes = vec![42];
        let s = Summary::from_slice(&mut sizes).unwrap();
        assert_eq!(s.n, 1);
        assert_eq!(s.min, 42);
        assert_eq!(s.p50, 42);
        assert_eq!(s.p99, 42);
        assert_eq!(s.max, 42);
    }

    #[test]
    fn hundred_elements_p50_is_50th() {
        let mut sizes: Vec<usize> = (1..=100).collect();
        let s = Summary::from_slice(&mut sizes).unwrap();
        // nearest-rank: p50 -> rank 50
        assert_eq!(s.p50, 50);
        // p95 -> rank 95
        assert_eq!(s.p95, 95);
        // p99 -> rank 99
        assert_eq!(s.p99, 99);
        assert_eq!(s.min, 1);
        assert_eq!(s.max, 100);
    }

    #[test]
    fn empty_returns_none() {
        let mut sizes: Vec<usize> = vec![];
        assert!(Summary::from_slice(&mut sizes).is_none());
    }
}
