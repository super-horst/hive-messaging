extern crate protobuf_codegen_pure;

use protobuf_codegen_pure::*;

fn main() {
    Codegen::new()
        .out_dir("src")
        .inputs(&["resources/messages.proto"])
        .includes(&["resources"])
        .run().expect("Codegen failed.");
}
