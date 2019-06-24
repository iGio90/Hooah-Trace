/**
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
 */
import * as hooah from "hooah-trace";

function onHookInstruction(hc: hooah.HooahContext) {
    // use for fun and profit
    // hc.context
    // hc.instruction
    // hc.print

    // the following code is meant to show the api exposed by htrace
    const mnemonic = hc.instruction.mnemonic;

    // count stp instructions
    let stpCount: number = 0;

    // build our print option, if we want to use it
    const printOptions: hooah.HooahPrintOptions = {};

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
    hooah.attach(target, onHookInstruction, {
        // -1 is endless
        count: -1,
        // do not trace outside the current range
        rangeOnly: false,
        // do not trace jumps in excluded modules (i.e libc / libSystem)
        excludedModules: []
    });
}
