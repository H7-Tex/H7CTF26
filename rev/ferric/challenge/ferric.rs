// Ferric - a Rust license validator. Enter the 16-char license to reveal the token.
// build: rustc -O -C strip=symbols ferric.rs -o ferric
use std::io::{self, Read, Write};
include!("data.rs");

fn check(key: &[u8]) -> bool {
    use std::hint::black_box;
    key.len() == 16 && key.iter().enumerate().all(|(i, &c)| {
        // black_box barriers stop the optimizer from const-folding the whole transform into a
        // direct `c == <license byte>` comparison — the player must actually reverse + invert it.
        let xk = black_box(XK[i]);
        let rot = black_box(ROT[i]);
        let ya = black_box(YA[i]);
        black_box((c ^ xk).rotate_left(rot as u32).wrapping_add(ya)) == black_box(TARGET[i])
    })
}

fn decrypt(key: &[u8]) -> String {
    let out: Vec<u8> = BLOB.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % 16] ^ ((i as u32).wrapping_mul(131).wrapping_add(7) as u8))
        .collect();
    String::from_utf8_lossy(&out).into_owned()
}

fn main() {
    let mut key = String::new();
    if let Some(a) = std::env::args().nth(1) {
        key = a;
    } else {
        print!("license: "); io::stdout().flush().ok();
        io::stdin().read_to_string(&mut key).ok();
    }
    let key = key.trim().as_bytes().to_vec();
    if check(&key) {
        println!("unlocked: {}", decrypt(&key));
    } else {
        println!("invalid license");
    }
}
