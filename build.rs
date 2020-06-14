extern crate protobuf_codegen_pure;
extern crate tonic_build;

use protobuf_codegen_pure::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Codegen::new()
        .out_dir("src/net")
        .inputs(&["resources/proto/messages.proto"])
        .includes(&["resources/proto"])
        .run()?;

    tonic_build::compile_protos("proto/accounts_svc.proto")?;

    Ok(())
}
