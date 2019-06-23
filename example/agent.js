/**
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
 */
const hooah = require('hooah-trace');

function onHookInstruction() {
    // use for fun and profit
    // this.context
    // this.instruction

    const mnemonic = this.instruction.mnemonic;
    if (mnemonic === 'ldr') {
        // print the instruction with register details
        this.print(true);
    } else {
        // print all other instructions with stripped details
        this.print();
    }
}

const target = Module.findExportByName(null, 'open');
const options = {
    // out callback for each instruction
    callback: onHookInstruction,
    // -1 is endless
    count: -1,
    // do not trace outside the current range
    rangeOnly: false,
    // do not trace jumps in excluded modules (i.e libc / libSystem)
    excludedModules: []
};

hooah.attach(target, options);
