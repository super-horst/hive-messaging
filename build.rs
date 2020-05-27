extern crate protobuf_codegen_pure;

fn main() {
	let protobuf_gen = protobuf_codegen_pure::run(protobuf_codegen_pure::Args {
		out_dir: "src",
		input: &["resources/messages.proto"],
		includes: &["resources"],
		customize: protobuf_codegen_pure::Customize {
			..Default::default()
		},
	});
	
    match protobuf_gen {
        Ok(_uptime) => _uptime,
        Err(err) => println!("protobuf code generation failed: {}", err),
    };
}
