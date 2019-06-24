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
interface HooahOptions {
    count?: number | undefined;
    rangeOnly?: boolean | undefined;
    excludedModules?: string[] | undefined;
}

interface AnyCpuContext extends PortableCpuContext {
    [name: string]: NativePointer;
}

export interface HooahContext {
    instruction: Instruction;
    context: PortableCpuContext;
    print: Function;
}

type HooahCallback = (h: HooahContext) => void;

const _red = '\x1b[0;31m';
const _green = '\x1b[0;32m';
const _yellow = '\x1b[0;33m';
const _blue = '\x1b[0;34m';
const _pink = '\x1b[0;35m';
const _cyan = '\x1b[0;36m';
const _bold = '\x1b[0;1m';
const _highlight = '\x1b[0;3m';
const _highlight_off = '\x1b[0;23m';
const _resetColor = '\x1b[0m';

const executionBlock = new Set<string>();
let targetTid = 0;
let onInstructionCallback: HooahCallback | null = null;

export function attach(target: NativePointer, callback: HooahCallback, params: HooahOptions = {}) {
    if (targetTid > 0) {
        console.log('Hooah is already tracing thread: ' + targetTid);
        return 1;
    }

    // parse options
    const { count = -1, rangeOnly = false, excludedModules = [] } = params;

    const interceptor = Interceptor.attach(target, function () {
        interceptor.detach();
        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return;
        }

        targetTid = Process.getCurrentThreadId();
        onInstructionCallback = callback;

        const startPc = this.context.pc;
        const startRange: RangeDetails | null = Process.findRangeByAddress(target);

        let inTrampoline = true;
        let instructionsCount = 0;

        Stalker.follow(targetTid, {
            transform: function (iterator: StalkerArm64Iterator | StalkerX86Iterator) {
                let instruction: X86Instruction | null | Arm64Instruction;
                let range: RangeDetails | null = null;

                let skipWholeBlock = false;

                while ((instruction = iterator.next()) !== null) {
                    if (skipWholeBlock) {
                        continue;
                    }

                    if (inTrampoline) {
                        const testAddress = instruction.address.sub(startPc).compare(0x30);
                        if (testAddress > 0 && testAddress < 0x30) {
                            inTrampoline = false;
                        }
                    }

                    if (!inTrampoline) {
                        if (range == null) {
                            range = Process.findRangeByAddress(instruction.address);
                        }

                        if (rangeOnly) {
                            if (startRange != null && range !== null &&
                                startRange.base.compare(range.base) !== 0) {
                                skipWholeBlock = true;
                                continue;
                            }
                        } else {
                            if (range) {
                                const file: FileMapping | undefined = range.file;
                                const haveFile = typeof file !== 'undefined';
                                if (excludedModules.length > 0) {
                                    if (haveFile) {
                                        let filtered = false;
                                        for (let i=0;i<excludedModules.length;i++) {
                                            if (file && file.path.indexOf(excludedModules[i]) >= 0) {
                                                filtered = true;
                                                break;
                                            }
                                        }
                                        if (filtered) {
                                            skipWholeBlock = true;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }

                        executionBlock.add(instruction.address.toString());

                        iterator.putCallout(<(context: PortableCpuContext) => void>onHitInstruction);

                        if (count > 0) {
                            instructionsCount++;
                            if (instructionsCount === count) {
                                detach();
                            }
                        }
                    }

                    iterator.keep();
                }
            }
        });
    });

    return 0;
}

export function detach(): void {
    Stalker.unfollow(targetTid);
    targetTid = 0;
}

function colorify(what: string, pat:string): string {
    let ret = '';
    if (pat.indexOf('bold') >= 0) {
        ret += _bold + ' ';
    } else if (pat.indexOf('highlight') >= 0) {
        ret += _highlight;
    }
    if (pat.indexOf('red') >= 0) {
        ret += _red;
    } else if (pat.indexOf('green') >= 0) {
        ret += _green;
    } else if (pat.indexOf('yellow') >= 0) {
        ret += _yellow;
    } else if (pat.indexOf('blue') >= 0) {
        ret += _blue;
    } else if (pat.indexOf('pink') >= 0) {
        ret += _pink;
    } else if (pat.indexOf('cyan') >= 0) {
        ret += _cyan
    }

    ret += what;
    if (pat.indexOf('highlight') >= 0) {
        ret += _highlight_off;
    }
    ret += _resetColor;
    return ret;
}

function regexColor(text: string): string {
    text = text.toString();
    //text = text.replace(/(\W)([a-z]{1,2}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'cyan') + "$3");
    text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify("$1", 'red'));
    return text;
}

function _getSpacer(space: number): string {
    let line = '';
    for (let i=0;i<space;i++) {
        line += ' ';
    }
    return line;
}

function _ba2hex(b: ArrayBuffer): string {
    let uint8arr = new Uint8Array(b);
    if (!uint8arr) {
        return '';
    }
    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr;
}

function _isJumpInstruction(instruction: Instruction): boolean {
    return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
}

function _getTelescope(address: NativePointer, isJumpInstruction: boolean) {
    let range = Process.findRangeByAddress(address);
    if (range !== null) {
        if (isJumpInstruction) {
            try {
                const instruction = Instruction.parse(address);
                let ret = colorify(instruction.mnemonic, 'green') + ' ' + regexColor(instruction.opStr);
                ret += _getSpacer(2) + '(';
                if (typeof range.file !== 'undefined') {
                    let parts = range.file.path.split('/');
                    ret += parts[parts.length - 1];
                }
                ret += '#' + address.sub(range.base);
                return ret + ')';
            } catch (e) {
                return null;
            }
        } else {
            try {
                let result: string | null = address.readUtf8String();
                if (result !== null) {
                    return result.replace('\n', ' ');
                }
            } catch (e) {
                try {
                    address = address.readPointer();
                    return address;
                } catch (e) {}
            }
        }
    }
    return null;
}

function _formatInstruction(address: NativePointer, instruction: Instruction,
    details: boolean, annotation: string): string {
    let line = colorify(address.toString(), 'red');

    const bytes = instruction.address.readByteArray(instruction.size);
    line += _getSpacer(4);
    if (bytes) {
        line += colorify(_ba2hex(bytes), 'yellow');
    } else {
        let _fix = '';
        for (let i=0;i<instruction.size;i++) {
            _fix += '00';
        }
        line += colorify(_fix, 'yellow');
    }
    line += _getSpacer(50 - line.length);
    line += colorify(instruction.mnemonic, 'green');
    line += _getSpacer(70 - line.length);
    line += regexColor(instruction.opStr);
    if (_isJumpInstruction(instruction) && !details) {
        let range = Process.findRangeByAddress(address);
        if (range !== null) {
            line += _getSpacer(4) + '(';
            if (typeof range.file !== 'undefined') {
                let parts = range.file.path.split('/');
                line += parts[parts.length - 1];
            }
            line += '#' + address.sub(range.base) + ')';
        }
    }

    if (typeof annotation !== 'undefined' && annotation !== '') {
        line += '\t\t@' + colorify(annotation, 'pink');
    }
    return line;
}

function _formatInstructionDetails(instruction: Instruction, context: PortableCpuContext): string {
    const anyContext = context as AnyCpuContext;
    const data: any[] = [];
    const visited: Set<string> = new Set<string>();

    let insn: Arm64Instruction | X86Instruction | null = null;
    if (Process.arch === 'arm64') {
       insn = instruction as Arm64Instruction;
    } else if (Process.arch === 'ia32' || Process.arch === 'x64') {
        insn = instruction as X86Instruction;
    }
    if (insn != null) {
        insn.operands.forEach((op: Arm64Operand | X86Operand) => {
            let reg: Arm64Register | X86Register | undefined;
            let value = null;
            let adds = 0;
            if (op.type === 'mem') {
                reg = op.value.base;
                adds = op.value.disp;
            } else if (op.type === 'reg') {
                reg = op.value;
            } else if (op.type === 'imm') {
                if (data.length > 0) {
                    value = data[data.length - 1][1];
                    if (value.constructor.name === 'NativePointer') {
                        data[data.length - 1][1].add(op.value);
                    }
                }
            }

            if (typeof reg !== 'undefined' && !visited.has(reg)) {
                visited.add(reg);
                try {
                    value = anyContext[reg];
                    if (typeof value !== 'undefined') {
                        value = anyContext[reg].add(adds);
                        data.push([reg, value, _getTelescope(value,
                            _isJumpInstruction(instruction))]);
                    } else {
                        //data.push([reg, 'register not found in context']);
                    }
                } catch (e) {
                    //data.push([reg, 'register not found in context']);
                }
            }
        });
    }

    let lines: string[] = [];
    let spacer = _getSpacer((instruction.address.toString().length / 2) - 1);
    console.log(data);
    data.forEach(row => {
        if (lines.length > 0) {
            lines[lines.length - 1] += '\n';
        }
        let line = spacer + '|---------' + spacer;
        line += colorify(row[0], 'blue') + ' = ' + regexColor(row[1]);
        if (row.length > 2 && row[2] !== null) {
            if (row[2].length === 0) {
                line += ' >> ' + colorify('0x0', 'red');
            } else {
                line += ' >> ' + regexColor(row[2]);
            }
        }
        lines.push(line);
    });

    let ret = '';
    lines.forEach( line => {
        ret += line;
    });
    return ret;
}

function onHitInstruction(context: PortableCpuContext, address: NativePointer): void {
    address = address || context.pc;

    if (!executionBlock.has(address.toString())) {
        console.log('stalker hit invalid instruction :\'(');
        detach();
        return;
    }

    const instruction: Instruction = Instruction.parse(address);

    if (onInstructionCallback !== null) {
        const ctx: HooahContext = {
            context: context,
            instruction: instruction,
            print(details: boolean, annotation: string): void {
                details = details || false;
                annotation = annotation || "";
                if (instruction) {
                    console.log(_formatInstruction(address, instruction, details, annotation));
                    if (details) {
                        console.log(_formatInstructionDetails(instruction, context))
                    }
                    if (_isJumpInstruction(instruction)) {
                        console.log('');
                    }
                }
            }
        };

        onInstructionCallback.apply({}, [ctx]);
    }

    executionBlock.delete(address.toString());
}
