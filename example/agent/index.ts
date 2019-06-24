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
import * as hooah from "hooah-trace";

function onHookInstruction(hc: hooah.HooahContext) {
    // use for fun and profit
    // this.context
    // this.instruction

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
