extern crate tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(
            &["proto/accounts_svc.proto", "proto/messages_svc.proto"],
            &["proto"],
        )?;


    Ok(())
}