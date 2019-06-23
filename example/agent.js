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
    target: target,
    callback: onHookInstruction
};

hooah.attach(options);
