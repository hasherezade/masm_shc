# masm_shc
## demos

Examples of the code to be refactored to shellcode:

1. popup.cpp - a simple "Hello World" Message Box
2. knock.cpp - a simple server, opening ports, waiting for a defined input, giving response

### Howto

1. Compile the example from C to MASM, using MSVC from a commadline

```
cl /c /GS- /FA <file>.cpp
```

2. Use masm_shc to clean the obtained MASM, inline the strings etc.

```
masm_shc.exe <file>.asm <cleaned_file>.asm
```

It should automatically resolve most of the issues. The remaining issues should be resolved manually following the diplayed hints. It will also inform if the Entry Point was changed

3. Compile the resulting file by MASM into a PE (use `ml` for 32-bit files and `ml64` for 64 bit files analogicaly)

```
ml <cleaned_file>.asm /link /entry:<my_entry_func>
```

4. Use PE-bear to dump the .text section from the resulting PE. This will be our shellcode.

5. Use runshc to test the shellcode (remember that the bitness of runshc must be the same as the bitness of the shellcode)

