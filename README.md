# Semi-automatic Code Deobfuscation

This repository contains slides, samples and code of the 2h code deobfuscation workshop at [r2con2020](https://rada.re/con/2020/). We use [`Miasm`](https://github.com/cea-sec/miasm) to automatically identify opaque predicates in the `X-Tunnel` APT128-malware using symbolic execution and SMT solving. Afterward, we automatically remove the opaque predicates via patching.


## Cutter Notes

To correctly disassembly the targeted function in `Cutter`, the analysis depth has to been increased:

```
e anal.depth=9999
af @ 0x491aa0
s 0x491aa0
```


## Contact

For more information, contact ([@mr_phrazer](https://twitter.com/mr_phrazer)).
