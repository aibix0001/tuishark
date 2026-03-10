use std::env;
use std::fs;
use std::path::Path;

fn main() {
    if cfg!(feature = "trace") {
        let out_dir = env::var("OUT_DIR").unwrap();
        let src = Path::new("ebpf/tuishark-ebpf");
        let dst = Path::new(&out_dir).join("tuishark-ebpf");

        if src.exists() {
            fs::copy(src, &dst).expect("Failed to copy eBPF binary to OUT_DIR");
        } else {
            panic!(
                "eBPF binary not found at {}. Build it first:\n\
                 cd tuishark-ebpf && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release",
                src.display()
            );
        }

        println!("cargo:rerun-if-changed=ebpf/tuishark-ebpf");
    }
}
