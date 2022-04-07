# RustyNeedle

A simple dropper for shellcode that leverages the power of...base64 encoding??

No seriously. And it works. Here's how:

## Usage

1. Create your shellcode however you like, be it with `msfvenom` or other tools. Export the raw shellcode file.

2. Use the encode.py script provided in this repository to create an encoded version of the shellcode. 

```bash
python3 encode.py [SHELLCODE_FILE] [B64_ITERATIONS] [OUT_FILE]
```

### Arguments

* `SHELLCODE_FILE`: raw shellcode file to encode
* `B64_ITERATIONS`: # of times to base64-encode the shellcode
* `OUT_FILE`: Resulting text file of the encoded shellcode. **NOTE:** this will be many times larger than the source!

