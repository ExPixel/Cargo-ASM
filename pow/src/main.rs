fn main() {
    for n in 0..10 {
        println!("2^{} = {:4}", n, pow(2, n));
    }
}

fn pow(base: u32, mut exp: u32) -> u32 {
    let mut out = 1;
    while exp > 0 {
        out *= base;
        exp -= 1;
    }
    out
}
