use bloom::{BloomFilter, ASMS};

pub struct Bloom {
    pub bloom_filter: BloomFilter,
}

impl Bloom {
    pub fn create_bloom_filter(rate: f32, filter_traffic: u32) -> Self {
        Bloom {
            bloom_filter: BloomFilter::with_rate(rate, filter_traffic),
        }
    }
    pub fn insert_value(&mut self, value: String) {
        self.bloom_filter.insert(&value);
    }

    pub fn check_value(&self, value: String) -> bool {
        self.bloom_filter.contains(&value)
    }
}
