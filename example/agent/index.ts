import {HooahTrace} from "hooah-trace";

function onHookInstruction(context: CpuContext, instruction: Instruction) {
    // console.log(JSON.stringify(context));
    // console.log(JSON.stringify(instruction));
    // console.log('');
}

const target = Module.findExportByName(null, 'open');
if (target) {
    Interceptor.attach(target, function () {
        HooahTrace.trace({
            // print the execution blocks
            printBlocks: true,

            // -1 is endless
            count: -1,

            // do not trace jumps in excluded modules (i.e libc / libSystem)
            filterModules: ['libc.so'],

            // you can trace specific instructions with
            // instructions: ['svc', 'ldr']

            // style block prints
            printOptions: {
                // yes please
                colored: true,

                // custom space between blocks
                treeSpaces: 8,

                // include involved register values data
                details: true
            }
        }, onHookInstruction);
    });
}
