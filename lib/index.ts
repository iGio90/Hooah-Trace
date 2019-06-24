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
class _HooahInstruction {
    address: NativePointer = ptr(0);
    mnemonic: string = '';
    opStr: string = '';
    groups: string[] = [];
    operands: any = [];
    size: number = 0;
    bytes: ArrayBuffer | null = null;

    constructor(instruction: X86Instruction | null | Arm64Instruction) {
        if (instruction != null) {
            this.address = instruction.address;
            this.mnemonic = instruction.mnemonic;
            this.opStr = instruction.opStr;
            this.groups = instruction.groups;
            this.operands = instruction.operands;
            this.size = instruction.size;
            this.bytes = instruction.address.readByteArray(this.size);
        }
    }
}

class _HooahTrace {
    _red= '\x1b[0;31m';
    _green = '\x1b[0;32m';
    _yellow = '\x1b[0;33m';
    _blue = '\x1b[0;34m';
    _pink = '\x1b[0;35m';
    _cyan = '\x1b[0;36m';
    _bold = '\x1b[0;1m';
    _highlight = '\x1b[0;3m';
    _highlight_off = '\x1b[0;23m';
    _resetColor = '\x1b[0m';

     colorify(what: string, pat:string): string {
        let ret = '';
        if (pat.indexOf('bold') >= 0) {
            ret += this._bold + ' ';
        } else if (pat.indexOf('highlight') >= 0) {
            ret += this._highlight;
        }
        if (pat.indexOf('red') >= 0) {
            ret += this._red;
        } else if (pat.indexOf('green') >= 0) {
            ret += this._green;
        } else if (pat.indexOf('yellow') >= 0) {
            ret += this._yellow;
        } else if (pat.indexOf('blue') >= 0) {
            ret += this._blue;
        } else if (pat.indexOf('pink') >= 0) {
            ret += this._pink;
        } else if (pat.indexOf('cyan') >= 0) {
            ret += this._cyan
        }

        ret += what;
        if (pat.indexOf('highlight') >= 0) {
            ret += this._highlight_off;
        }
        ret += this._resetColor;
        return ret;
    };

    regexColor(text: string): string {
        text = text.toString();
        //text = text.replace(/(\W)([a-z]{1,2}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'cyan') + "$3");
        text = text.replace(/(0x[0123456789abcdef]+)/gm, this.colorify("$1", 'red'));
        return text;
    };

    tid = 0;
    callback: Function | null = null;
    executionBlock = new Map<string, _HooahInstruction>();

    static _getSpacer(space: number): string {
        let line = '';
        for (let i=0;i<space;i++) {
            line += ' ';
        }
        return line;
    };

    static _ba2hex(b: ArrayBuffer): string {
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
    };

    static _isJumpInstruction(instruction: Instruction | _HooahInstruction): boolean {
        return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
    };

    static _getArg(args: Map<string, any> | null, key: string, def: any): any {
        def = def || null;
        if (args === null || !args.has(key)) {
            return def;
        }
        return args.get(key);
    };

    _getTelescope(address: NativePointer, isJumpInstruction: boolean) {
        let range = Process.findRangeByAddress(address);
        if (range !== null) {
            if (isJumpInstruction) {
                try {
                    const instruction = Instruction.parse(address);
                    let ret = this.colorify(instruction.mnemonic, 'green') + ' ' + this.regexColor(instruction.opStr);
                    ret += _HooahTrace._getSpacer(2) + '(';
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
    };

    _formatInstruction(address: NativePointer, instruction: _HooahInstruction,
                       details: boolean, annotation: string): string {
        let line = this.colorify(address.toString(), 'red');
        if (instruction.bytes !== null) {
            line += _HooahTrace._getSpacer(4);
            line += this.colorify(_HooahTrace._ba2hex(instruction.bytes), 'yellow');
        }
        line += _HooahTrace._getSpacer(50 - line.length);
        line += this.colorify(instruction.mnemonic, 'green');
        line += _HooahTrace._getSpacer(70 - line.length);
        line += this.regexColor(instruction.opStr);
        if (_HooahTrace._isJumpInstruction(instruction) && !details) {
            let range = Process.findRangeByAddress(address);
            if (range !== null) {
                line += _HooahTrace._getSpacer(4) + '(';
                if (typeof range.file !== 'undefined') {
                    let parts = range.file.path.split('/');
                    line += parts[parts.length - 1];
                }
                line += '#' + address.sub(range.base) + ')';
            }
        }

        if (typeof annotation !== 'undefined' && annotation !== '') {
            line += '\t\t@' + this.colorify(annotation, 'pink');
        }
        return line;
    };

    _formatInstructionDetails(instruction: _HooahInstruction, context: PortableCpuContext): string {
        const anyContext = context as AnyCpuContext;
        const data: any[] = [];
        const visited: Set<string> = new Set<string>();
        instruction.operands.forEach((op: Arm64Operand | X86Operand) => {
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
                        data.push([reg, value, this._getTelescope(value,
                            _HooahTrace._isJumpInstruction(instruction))]);
                    } else {
                        //data.push([reg, 'register not found in context']);
                    }
                } catch (e) {
                    //data.push([reg, 'register not found in context']);
                }
            }
        });
        let lines: string[] = [];
        let spacer = _HooahTrace._getSpacer((instruction.address.toString().length / 2) - 1);
        data.forEach(row => {
            if (lines.length > 0) {
                lines[lines.length - 1] += '\n';
            }
            let line = spacer + '|---------' + spacer;
            line += this.colorify(row[0], 'blue') + ' = ' + this.regexColor(row[1]);
            if (row.length > 2 && row[2] !== null) {
                if (row[2].length === 0) {
                    line += ' >> ' + this.colorify('0x0', 'red');
                } else {
                    line += ' >> ' + this.regexColor(row[2]);
                }
            }
            lines.push(line);
        });

        let ret = '';
        lines.forEach( line => {
           ret += line;
        });
        return ret;
    };

    onHitInstruction(context: PortableCpuContext, address: NativePointer): void {
        address = address || context.pc;
        const instruction: _HooahInstruction | undefined = this.executionBlock.get(address.toString());

        if (typeof instruction === 'undefined') {
            console.log('stalker hit invalid instruction :\'(');
            _HooahTrace.detach();
            return;
        }

        if (this.callback !== null) {
            this.callback.apply({
                context: context,
                instruction: instruction,
                print(details: boolean, annotation: string) {
                    details = details || false;
                    annotation = annotation || "";
                    console.log(this._formatInstruction(address, instruction, details, annotation));
                    if (details) {
                        console.log(this._formatInstructionDetails(instruction, context))
                    }
                    if (typeof instruction !== 'undefined' && this._isJumpInstruction(instruction)) {
                        console.log('');
                    }
                }
            });
        }

        this.executionBlock.delete(address.toString());
    };

    attach(target: NativePointer, args: Map<string, any> | null) {
        if (this.tid > 0) {
            console.log('Hooah is already tracing thread: ' + this.tid);
        }

        // parse options
        args = args || null;
        const callback = _HooahTrace._getArg(args, 'callback', null);
        const count = _HooahTrace._getArg(args, 'count', -1);
        const rangeOnly = _HooahTrace._getArg(args, 'rangeOnly', false);
        const excludedModules = _HooahTrace._getArg(args, 'excludedModules', []);

        const interceptor = Interceptor.attach(target, function () {
            interceptor.detach();
            if (HooahTrace.tid > 0) {
                console.log('Hooah is already tracing thread: ' + HooahTrace.tid);
                return;
            }

            HooahTrace.tid = Process.getCurrentThreadId();
            HooahTrace.callback = callback;

            const startPc = this.context.pc;
            const startRange: RangeDetails | null = Process.findRangeByAddress(target);

            let inTrampoline = true;
            let instructionsCount = 0;

            Stalker.follow(HooahTrace.tid, {
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

                            HooahTrace.executionBlock.set(instruction.address.toString(),
                                new _HooahInstruction(instruction));

                            iterator.putCallout(<(context: CpuContext) => void>HooahTrace.onHitInstruction);

                            if (count > 0) {
                                instructionsCount++;
                                if (instructionsCount === count) {
                                    _HooahTrace.detach();
                                }
                            }
                        }

                        iterator.keep();
                    }
                }
            });
        });
    };

    static detach(): void {
        Stalker.unfollow(HooahTrace.tid);
        HooahTrace.tid = 0;
    };
}

interface AnyCpuContext extends PortableCpuContext {
    [name: string]: NativePointer;
}

export const HooahTrace = new _HooahTrace();
