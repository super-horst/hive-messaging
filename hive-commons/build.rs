extern crate cfg_if;
extern crate tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = tonic_build::configure().out_dir("./src/model");

    cfg_if::cfg_if! {
        if #[cfg(not(feature = "transport"))] {
            builder = builder.build_server(false).build_client(false);
        }
    }

    builder.compile(
        &["proto/accounts_svc.proto", "proto/messages_svc.proto"],
        &["proto"],
    )?;

    Ok(())
}
