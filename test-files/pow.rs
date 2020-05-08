fn main() {
    for x in 0..16 {
        let px = pow(2, x);
        println!("pow(2, {}) = {}", x, px);
    }
}

fn pow(base: u64, mut exp: u64) -> u64 {
    let mut out = 1;
    while exp > 0 {
        out *= base;
        exp -= 1;
    }
    out
}
