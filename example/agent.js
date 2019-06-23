const hooah = require('hooah-trace');

function onHookInstruction() {
    // use for fun and profit
    // this.context
    // this.instruction
}

const target = Module.findExportByName(null, 'open');
const options = {
    // out callback for each instruction
    callback: onHookInstruction,
    // -1 is endless
    count: -1,
    // log instructions
    verbose: true,
    // with details
    details: true
};

hooah.attach(target, options);
