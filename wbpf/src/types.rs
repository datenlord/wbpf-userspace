use fnv::FnvBuildHasher;
use indexmap::{IndexMap, IndexSet};

pub type FnvIndexMap<K, V> = IndexMap<K, V, FnvBuildHasher>;
pub type FnvIndexSet<T> = IndexSet<T, FnvBuildHasher>;
