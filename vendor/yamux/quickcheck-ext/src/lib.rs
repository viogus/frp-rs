//! Locally restored copy of upstream `paritytech/yamux`'s `quickcheck-ext`
//! crate (repo path `quickcheck-ext/`), vendored so that `vendor/yamux`'s test
//! targets build standalone. Upstream yamux declares it as a path
//! dev-dependency; the crates.io tarball cannot carry a path dependency, so
//! cargo's manifest normalization dropped it and the published 0.14.1 test
//! targets do not build on their own. Only `GenRange`/`SliceRandom` are used by
//! the yamux tests. Apache-2.0 OR MIT, same license as yamux.

pub use quickcheck::*;

use core::ops::Range;
use num_traits::sign::Unsigned;

pub trait GenRange {
    fn gen_range<T: Unsigned + Arbitrary + Copy>(&mut self, _range: Range<T>) -> T;

    fn gen_index(&mut self, ubound: usize) -> usize {
        if ubound <= (u32::MAX as usize) {
            self.gen_range(0..ubound as u32) as usize
        } else {
            self.gen_range(0..ubound)
        }
    }
}

impl GenRange for Gen {
    fn gen_range<T: Unsigned + Arbitrary + Copy>(&mut self, range: Range<T>) -> T {
        <T as Arbitrary>::arbitrary(self) % (range.end - range.start) + range.start
    }
}

pub trait SliceRandom {
    fn shuffle<T>(&mut self, arr: &mut [T]);
    fn choose_multiple<'a, T>(
        &mut self,
        arr: &'a [T],
        amount: usize,
    ) -> std::iter::Take<std::vec::IntoIter<&'a T>> {
        let mut v: Vec<&T> = arr.iter().collect();
        self.shuffle(&mut v);
        v.into_iter().take(amount)
    }
}

impl SliceRandom for Gen {
    fn shuffle<T>(&mut self, arr: &mut [T]) {
        for i in (1..arr.len()).rev() {
            // invariant: elements with index > i have been locked in place.
            arr.swap(i, self.gen_index(i + 1));
        }
    }
}
