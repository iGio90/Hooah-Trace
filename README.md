# Hooah Trace

a simple yet powerful instruction tracing for frida.

an hook is placed to target provided which start the instruction tracing using frida Stalker.

currently supporting arm64 and x64

## when you want to use this
when you need to trace at single instruction and perform additional operations or alter the code flow


## install

```$xslt
git clone https://github.com/iGio90/Hooah-Trace.git
npm install
npm link
```

### try it out
```$xslt
cd example
npm link hooah-trace
npm install
npm run watch

# make your edits to index.ts
# inject the agent (quick att.py)
```

example code
```typescript
import * as htrace from "hooah-trace";

function onHookInstruction(hc: htrace.HooahContext) {
    // use for fun and profit
    // hc.context
    // hc.instruction
    // hc.print

    // the following code is meant to show the api exposed by htrace
    const mnemonic = hc.instruction.mnemonic;

    // count stp instructions
    let stpCount: number = 0;

    // build our print option, if we want to use it
    const printOptions: htrace.HooahPrintOptions = {};

    // yes please
    printOptions.colored = true;

    if (mnemonic === 'ldr') {
        // print the instruction with register details
        printOptions.details = true;
    } else if (mnemonic === 'stp') {
        // add some notes to stp instructions
        stpCount += 1;
        printOptions.annotation = 'stpCount: ' + stpCount;
    } else {
        // print all other instructions with default options
    }

    hc.print(printOptions);
}

const target = Module.findExportByName(null, 'open');
if (target) {
    htrace.attach(target, onHookInstruction, {
        // -1 is endless
        count: -1,
        // do not trace outside the current range
        rangeOnly: false,
        // do not trace jumps in excluded modules (i.e libc / libSystem)
        excludedModules: []
    });
}
```

### example output
```$xslt
0x732ebbe774    f65701a9      stp            x22, x21, [sp, #0x10]
0x732ebbe778    f44f02a9      stp            x20, x19, [sp, #0x20]
0x732ebbe77c    fd7b03a9      stp            x29, x30, [sp, #0x30]
0x732ebbe780    fdc30091      add            x29, sp, #0x30
0x732ebbe784    a00300b0      adrp           x0, #0x732ec33000
0x732ebbe788    00601791      add            x0, x0, #0x5d8
0x732eb5c858    b00600b0      adrp           x16, #0x732ec31000
0x732eb5c85c    11d640f9      ldr            x17, [x16, #0x1a8]
0x732eb5c860    10a20691      add            x16, x16, #0x1a8
0x732ebc6de0    f30f1ef8      str            x19, [sp, #-0x20]!
0x732ebc6de4    fd7b01a9      stp            x29, x30, [sp, #0x10]
0x732ebc6de8    fd430091      add            x29, sp, #0x10
0x732ebc6dec    f30300aa      mov            x19, x0
0x732ebc6df0    68024079      ldrh           w8, [x19]
0x732ebc6df4    003d0012      and            w0, w8, #0xffff
0x732ebc6df8    1f051272      tst            w8, #0xc000
0x732ebc6e00    08001312      and            w8, w0, #0x2000
0x732ebc6e04    09010032      orr            w9, w8, #1
0x732ebc6e08    6afe5f48      ldaxrh         w10, [x19]
0x732ebc6e0c    5f21286b      cmp            w10, w8, uxth
0x732ebc6e10    81000054      b.ne           #0x732ebc6e20

0x732ebc6e14    697e0a48      stxrh          w10, w9, [x19]
0x732ebc6e08    6afe5f48      ldaxrh         w10, [x19]
0x732ebc6e0c    5f21286b      cmp            w10, w8, uxth
0x732ebc6e10    81000054      b.ne           #0x732ebc6e20

0x732ebc6e14    697e0a48      stxrh          w10, w9, [x19]
0x732ebc6e08    6afe5f48      ldaxrh         w10, [x19]
0x732ebc6e0c    5f21286b      cmp            w10, w8, uxth
0x732ebc6e10    81000054      b.ne           #0x732ebc6e20
```

### example output with details
```
0x7249e06254    00013fd6    blr      x8
     |---------     x8 = 0x7249b47c54 >> str x28, [sp, #-0x60]!  (libtarget.so#0x474c54)

jumping to range 0x72496d3000 >> /data/app/com.target/lib/arm64/libtarget.so
0x7249b47c54    fc0f1af8    str      x28, [sp, #-0x60]!
     |---------     x28 = 0x72496cda5c >> 0xa9017bfdf81e0ff3
     |---------     sp = 0x7249505420 >> 0x8020080280200802
0x7249b47c58    fa6701a9    stp      x26, x25, [sp, #0x10]
     |---------     x26 = 0x73303715e0 >> 0x73303715e0
     |---------     x25 = 0x7249408000
     |---------     sp = 0x7249505430 >> 0x0
0x7249b47c5c    f85f02a9    stp      x24, x23, [sp, #0x20]
     |---------     x24 = 0x7249505570 >> 
     |---------     x23 = 0x58
     |---------     sp = 0x7249505440 >> 0x0
0x7249b47c60    f65703a9    stp      x22, x21, [sp, #0x30]
     |---------     x22 = 0x5f0200005f02
     |---------     x21 = 0x72495054f0 >> 0x724a86c4f0
     |---------     sp = 0x7249505450 >> 0x0
0x7249b47c64    f44f04a9    stp      x20, x19, [sp, #0x40]
     |---------     x20 = 0x72495054f0 >> 0x724a86c4f0
     |---------     x19 = 0x72a0aaa940 >> 0x0
     |---------     sp = 0x7249505460 >> 0x8020080280200802
0x7249b47c68    fd7b05a9    stp      x29, x30, [sp, #0x50]
     |---------     fp = 0x7249505490 >> 0x72495054b0
     |---------     lr = 0x7249e06258 >> 0xf900027ff9400274
     |---------     sp = 0x7249505470 >> 0֣+s
0x7249b47c6c    fd430191    add      x29, sp, #0x50
     |---------     fp = 0x7249505490 >> 0x72495054b0
     |---------     sp = 0x7249505420 >> 0x72496cda5c
```

---
## roadmap
* add syscall map for syscall tracing
* add medium-level decompilation
* add asm relocation

## changelog

**2019.06.24**
```
* added rangeOnly option
* added excludedModules option
* make output colorized
* improve telescope, show symbols on jumps
* added back print() api with details, color and annotations
* some logic improvements
```

---

```
Copyright (c) 2019 Giovanni (iGio90) Rocca

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```