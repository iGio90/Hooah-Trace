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
![Alt text](https://raw.githubusercontent.com/iGio90/Hooah-Trace/master/3.PNG "HooahTrace 3")

### example output with details
![Alt text](https://raw.githubusercontent.com/iGio90/Hooah-Trace/master/1.PNG "HooahTrace 1")

![Alt text](https://raw.githubusercontent.com/iGio90/Hooah-Trace/master/2.PNG "HooahTrace 2")


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