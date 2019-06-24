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
        // do not trace jumps in excluded modules (i.e libc / libSystem)
        filterModules: ['libc.so']
    });
}
