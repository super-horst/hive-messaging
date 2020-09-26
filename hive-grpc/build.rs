extern crate tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .out_dir("./src/")
        .compile(
            &["proto/accounts_svc.proto", "proto/messages_svc.proto"],
            &["proto"],
        )?;


    Ok(())
}
