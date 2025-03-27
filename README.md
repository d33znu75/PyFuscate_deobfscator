# Python Deobfuscator for Py-Fuscate
This Python script is designed to deobfuscate Python scripts encoded using Py-Fuscate.<br>
It supports multiple compression and encoding methods, recursively decompresses and unmarshals obfuscated data, and disassembles bytecode.

### Features
- Supports all Compression Methods used by Py-Fuscate: zlib, lzma, bz2, gzip, base64
- Recursive Decompression: Automatically detects and processes nested obfuscation layers.
- Bytecode Disassembly: Disassembles Python bytecode into human-readable instructions.

### How It Works
1 - Detection: The script scans the obfuscated file for known compression and encoding patterns (e.g., zlib.decompress, lzma.decompress, etc.).<br>
2 - Decompression: It decompresses the data using the appropriate method (e.g., zlib, lzma, bz2, gzip, or base64).<br>
3 - Unmarshalling: The decompressed data is unmarshalled using Python's marshal module to extract the bytecode.<br>
4 - Disassembly: The bytecode is disassembled into human-readable instructions using Python's dis module.<br>

### Usage
```py
python3 deobfuscate.py <input_file>
```

### Example output
example output for obfuscated : ```print("warflower")```

```
0 RESUME 0 ()
2 PUSH_NULL None ()
4 LOAD_NAME 0 (print)
6 LOAD_CONST 0 ('warflower')
8 CALL 1 ()
16 POP_TOP None ()
18 RETURN_CONST 1 (None)
```
