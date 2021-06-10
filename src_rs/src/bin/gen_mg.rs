use std::io::Write;
use std::time::Instant;
use std::path::Path;
use epir::ecelgamal::{mg_default_path, DEFAULT_MMAX_MOD, DecryptionContext};

pub fn main() {
    let path_default = mg_default_path().expect("Failed to determine default mG.bin path.");
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if (args[1] == "-h") || (args[1] == "--help") {
            println!("usage: {} [PATH={} [MMAX_MOD=24]]\n", args[0], path_default);
            return;
        }
    }
    let path = if args.len() > 1 { args[1].clone() } else { path_default };
    let mmax_mod = if args.len() > 2 {
        args[2].parse::<u8>().expect("Failed to parse MMAX_MOD as an integer.")
    } else { DEFAULT_MMAX_MOD };
    let mmax = 1 << mmax_mod;
    if Path::new(&path).exists() {
        println!("The file mG.bin already exists. Do nothing.");
        return;
    }
    let begin_compute = Instant::now();
    let mut mgs = DecryptionContext::generate_no_sort(Some(mmax), |pc| {
        if pc % 1000_000 == 0 {
            println!("{:8} of {:8} points computed ({:3.2}%)", pc, mmax, 100f64 * (pc as f64 / mmax as f64));
        }
    });
    println!("Computation done in {}ms.", begin_compute.elapsed().as_millis());
    let begin_sort = Instant::now();
    DecryptionContext::generate_sort(&mut mgs);
    println!("Points sorted in {}ms.", begin_sort.elapsed().as_millis());
    let dec_ctx = DecryptionContext::from(mgs);
    let begin_write = Instant::now();
    let mut file = std::fs::File::create(&path).expect("Failed to open mG.bin for write.");
    file.write_all(&Vec::from(dec_ctx)[..]).expect("Failed to write to mG.bin.");
    println!("Output written in {}ms.", begin_write.elapsed().as_millis());
}
