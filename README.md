# Hooah Trace

a simple yet powerful instruction tracing for frida.

an hook is placed to target provided which start the instruction tracing using frida Stalker.

currently supporting only 64bit arch as we rely on stalker

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
    // this.context
    // this.instruction

    const mnemonic = hc.instruction.mnemonic;
    if (mnemonic === 'ldr') {
        // print the instruction with register details
        hc.print(true);
    } else if (mnemonic === 'stp') {
        // add some notes to stp instructions
        hc.print(false, "stp " + hc.context.pc)
    } else {
        // print all other instructions with stripped details
        hc.print();
    }
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
0x732eb6d178    53d03bd5      mrs            x19, tpidr_el0
0x732eb6d17c    e61f03ad      stp            q6, q7, [sp, #0x60]
0x732eb6d180    e41702ad      stp            q4, q5, [sp, #0x40]
0x732eb6d184    0a008852      mov            w10, #0x4000
0x732eb6d188    e20f01ad      stp            q2, q3, [sp, #0x20]
0x732eb6d18c    e803012a      mov            w8, w1
0x732eb6d190    e00700ad      stp            q0, q1, [sp]
0x732eb6d194    0a08a072      movk           w10, #0x40, lsl #16
0x732eb6d198    a69f3ba9      stp            x6, x7, [x29, #-0x48]
0x732eb6d19c    0a010a0a      and            w10, w8, w10
0x732eb6d1a0    a4973aa9      stp            x4, x5, [x29, #-0x58]
0x732eb6d1a4    5f115071      cmp            w10, #0x404, lsl #12
0x732eb6d1a8    a28f39a9      stp            x2, x3, [x29, #-0x68]
0x732eb6d1ac    691640f9      ldr            x9, [x19, #0x28]
0x732eb6d1b0    a9831ef8      stur           x9, [x29, #-0x18]
0x732eb6d1bc    e3031f2a      mov            w3, wzr
0x732eb6d214    690c8012      mov            w9, #-0x64
0x732eb6d218    e10300aa      mov            x1, x0
0x732eb6d21c    e203082a      mov            w2, w8
0x732eb6d220    e003092a      mov            w0, w9
0x732ebb2880    080780d2      mov            x8, #0x38
0x732ebb2884    010000d4      svc            #0
0x732ebb2888    1f0440b1      cmn            x0, #1, lsl #12
0x732ebb288c    009480da      cneg           x0, x0, hi
0x732eb6d228    681640f9      ldr            x8, [x19, #0x28]
0x732eb6d22c    a9835ef8      ldur           x9, [x29, #-0x18]
0x732eb6d230    1f0109eb      cmp            x8, x9
0x732eb6d238    fd7b4fa9      ldp            x29, x30, [sp, #0xf0]
0x732eb6d23c    f37340f9      ldr            x19, [sp, #0xe0]
0x732eb6d240    ff030491      add            sp, sp, #0x100
0x732ebbeba8    f503002a      mov            w21, w0
0x732ebbebac    bf060031      cmn            w21, #1
0x732ebbe770    f85fbca9      stp            x24, x23, [sp, #-0x40]!
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
## Changelog

**2019.06.24**
```
* added rangeOnly option
* added excludedModules option
* make output colorized
* improve telescope, show symbols on jumps
* added back this.print() instruction with details
* added notes to this.print
* some logic improvements
```

---

```
Hooah Trace (htrace) - Copyright (C) 2019 Giovanni (iGio90) Rocca

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
```