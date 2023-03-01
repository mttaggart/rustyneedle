import sys
from base64 import b64encode

# Grab command line args
IN_FILE = sys.argv[1]
B64_ITERS = int(sys.argv[2])
OUT_FILE = sys.argv[3]

# Retrieve raw shellcode
with open(IN_FILE, "rb") as f:
    shellcode = f.read()

# B64 Encode the shellcode
encoded_shellcode = shellcode

for i in range(B64_ITERS):
    encoded_shellcode = b64encode(encoded_shellcode)

# Write out the file
with open(OUT_FILE, "wb") as f:
    f.write(encoded_shellcode)