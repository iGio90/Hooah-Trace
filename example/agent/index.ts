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
import * as htrace from "hooah-trace";

function onHookInstruction(hc: htrace.HooahContext) {
    // use for fun and profit
    // this.context
    // this.instruction

    const mnemonic = hc.instruction.mnemonic;
    if (mnemonic === 'ldr') {
        // print the instruction with register details
        hc.print(false);
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
