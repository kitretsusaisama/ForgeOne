use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Tell cargo to rerun this build script if the proto files change
    println!("cargo:rerun-if-changed=proto/network.proto");
    
    // Compile the proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/api/proto")
        .compile(&["proto/network.proto"], &["proto"])?;
    
    Ok()
}