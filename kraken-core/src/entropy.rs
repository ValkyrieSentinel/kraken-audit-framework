use std::collections::HashMap;


pub fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    let mut total_chars = 0.0;

    for c in data.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
        total_chars += 1.0;
    }

    let mut entropy = 0.0;
    for &count in frequencies.values() {
        let p = count as f64 / total_chars;
        entropy -= p * p.log2();
    }

    entropy
}


pub fn is_suspicious(data: &str) -> bool {
    let e = calculate_entropy(data);
    e > 4.5 && data.len() > 20
}