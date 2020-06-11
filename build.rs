extern crate protobuf_codegen_pure;

use protobuf_codegen_pure::*;

fn main() {
    Codegen::new()
        .out_dir("src/net")
        .inputs(&["resources/proto/messages.proto"])
        .includes(&["resources/proto"])
        .run().expect("Codegen failed.");
}
