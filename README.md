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
import {HooahTrace} from "hooah-trace";

function onHookInstruction(context: CpuContext, instruction: Instruction) {
    // console.log(JSON.stringify(context));
    // console.log(JSON.stringify(instruction));
    // console.log('');
}

const target = Module.findExportByName(null, 'open');
if (target) {
    Interceptor.attach(target, function () {
        HooahTrace.trace(onHookInstruction, {
            // print the execution blocks
            printBlocks: true,

            // -1 is endless
            count: -1,

            // do not trace jumps in excluded modules (i.e libc / libSystem)
            filterModules: ['libc.so'],

            // style block prints
            printOptions: {
                // yes please
                colored: true,

                // custom space between blocks
                treeSpaces: 8,

                // include involved register values data
                details: true
            }
        });
    });
}
```

### example output
```$xslt
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

### example output with treeSpaces

```
             0x732eb5fda0 (libc.so#0x1dda0)                              0004803d   str       q0, [x0, #0x10]
             0x732eb5fda4 (libc.so#0x1dda4)                              000001ad   stp       q0, q0, [x0, #0x20]
             0x732eb5fda8 (libc.so#0x1dda8)                              80003fad   stp       q0, q0, [x4, #-0x20]
             0x732eb5fdac (libc.so#0x1ddac)                              c0035fd6   ret       

       0x722576555c (libg.so#0x42155c)                             e0031d32   orr       w0, wzr, #8
       0x7225765560 (libg.so#0x421560)                             02bb1194   bl        #0x7225bd4168 (libg.so#0x890168)

             0x7225bd4168 (libg.so#0x890168)                             f30f1ef8   str       x19, [sp, #-0x20]!
             0x7225bd416c (libg.so#0x89016c)                             fd7b01a9   stp       x29, x30, [sp, #0x10]
             0x7225bd4170 (libg.so#0x890170)                             fd430091   add       x29, sp, #0x10
             0x7225bd4174 (libg.so#0x890174)                             1f0000f1   cmp       x0, #0
```

---
## roadmap
* add syscall map for syscall tracing
* add medium-level decompilation
* add asm relocation

## changelog

**2019.06.27**
```
* refactored to be more flexible and tiny
* removed print() in favor of print blocks option
* added graph highlithing execution blocks
* various minor improvements
```
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