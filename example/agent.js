const hooah = require('hooah-trace');

function onHookInstruction() {
    // log this hook
    this.print();

    // use for fun and profit
    // this.context
    // this.instruction
}

const target = Module.findExportByName(null, 'open');
const options = {
    // out callback for each instruction
    callback: onHookInstruction,
    // -1 is endless
    count: -1
};

hooah.attach(target, options);
