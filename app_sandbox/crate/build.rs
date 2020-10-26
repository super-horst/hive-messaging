use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _output = Command::new("./generate_js_protos.sh")
        .output()
        .expect("Failed to execute command");

    Ok(())
}
