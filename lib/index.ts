import * as OnLoadInterceptor from "frida-onload"
import {doesNotReject} from "assert";


interface AnyCpuContext extends PortableCpuContext {
    [name: string]: NativePointer;
}

export interface HooahPrintOptions {
    colored?: boolean | undefined;
    details?: boolean | undefined;
    annotation?: string | undefined;
    treeSpaces?: number | undefined;
}

interface HooahOptions {
    count?: number | undefined;
    filterModules?: string[] | undefined;
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

const callMnemonics = ['call', 'bl', 'blx', 'blr', 'bx'];

let treeTrace: NativePointer[] = [];
let targetTid = 0;
let onInstructionCallback: HooahCallback | null = null;
let moduleMap = new ModuleMap();
let filtersModuleMap: ModuleMap | null = null;

export function attach(target: NativePointer, callback: HooahCallback, params: HooahOptions = {}) {
    if (targetTid > 0) {
        console.log('Hooah is already tracing thread: ' + targetTid);
        return 1;
    }

    const { count = -1, filterModules = [] } = params;

    const interceptor = Interceptor.attach(target, function () {
        interceptor.detach();
        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return;
        }

        targetTid = Process.getCurrentThreadId();
        onInstructionCallback = callback;

        const startPc = this.context.pc;

        moduleMap.update();
        filtersModuleMap = new ModuleMap(module => {
            let found = false;
            filterModules.forEach(filter => {
               if (module.name.indexOf(filter) >= 0) {
                   found = true;
               }
            });
            return found;
        });

        OnLoadInterceptor.attach((name: string, base: NativePointer) => {
            moduleMap.update();
            if (filtersModuleMap) {
                filtersModuleMap.update();
            }
        });

        let inTrampoline = true;
        let instructionsCount = 0;

        Stalker.follow(targetTid, {
            transform: function (iterator: StalkerArm64Iterator | StalkerX86Iterator) {
                let instruction: Arm64Instruction | X86Instruction | null;

                // prevent blocks with ldaxr instruction for the moment
                let safeBlockCheck = false;

                let killBlock = false;

                while ((instruction = iterator.next()) !== null) {
                    if (killBlock) {
                        iterator.keep();
                        continue;
                    }

                    if (inTrampoline) {
                        const testAddress = instruction.address.sub(startPc).compare(0x30);
                        if (testAddress < 0) {
                            inTrampoline = false;
                        }
                    }

                    if (!inTrampoline) {
                        if (!safeBlockCheck) {
                            safeBlockCheck = true;
                            let insn: Instruction = instruction;
                            while (true) {
                                if (isJumpInstruction(insn)) {
                                    break;
                                }
                                if (insn.mnemonic === 'ldaxr') {
                                    killBlock = true;
                                    break;
                                }
                                try {
                                    insn = Instruction.parse(insn.next);
                                } catch (e) {
                                    break
                                }
                            }
                        }

                        if (filtersModuleMap && filtersModuleMap.has(instruction.address)) {
                            killBlock = true;
                        }

                        if (!killBlock) {
                            iterator.putCallout(<(context: PortableCpuContext) => void>onHitInstruction);
                        }
                    }

                    if (count > 0) {
                        instructionsCount++;
                        if (instructionsCount === count) {
                            detach();
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
    OnLoadInterceptor.detach();
    filtersModuleMap = null;
    onInstructionCallback = null;
    treeTrace = [];
    targetTid = 0;
}

function applyColorFilters(text: string): string {
    text = text.toString();
    text = text.replace(/(\W|^)([a-z]{1,4}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'blue') + "$3");
    text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify("$1", 'red'));
    text = text.replace(/#(\d+)/gm, "#" + colorify("$1", 'red'));
    return text;
}

function ba2hex(b: ArrayBuffer): string {
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

function colorify(what: string, pat:string): string {
    if (pat === 'filter') {
        return applyColorFilters(what);
    }
    let ret = '';
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
    if (pat.indexOf('bold') >= 0) {
        ret += _bold;
    } else if (pat.indexOf('highlight') >= 0) {
        ret += _highlight;
    }

    ret += what;
    if (pat.indexOf('highlight') >= 0) {
        ret += _highlight_off;
    }
    ret += _resetColor;
    return ret;
}

function formatInstruction(
    context: PortableCpuContext,
    address: NativePointer,
    instruction: Instruction,
    details: boolean,
    annotation: string,
    colored: boolean,
    treeSpace: number): string {

    const anyCtx = context as AnyCpuContext;
    let line = "";
    let coloredLine = "";
    let part: string;
    let intTreeSpace = 0;
    let spaceAtOpStr: number;

    const append = function(what: string, color: string | null): void {
        line += what;
        if (colored) {
            if (color) {
                coloredLine += colorify(what, color);
            } else {
                coloredLine += what;
            }
        }
    };

    const appendModuleInfo = function(address: NativePointer): void {
        const module = moduleMap.find(address);
        if (module !== null) {
            append(' (', null);
            append(module.name, 'green bold');
            part = '#';
            append(part, null);
            part = address.sub(module.base).toString();
            append(part, 'red');
            part = ')';
            append(part, null);
        }
    };

    const addSpace = function(count: number): void {
        append(getSpacer(count + intTreeSpace - line.length), null);
    };

    if (treeSpace > 0 && treeTrace.length > 0) {
        intTreeSpace = (treeTrace.length) * treeSpace;
        append(getSpacer(intTreeSpace), null);
    }

    append(address.toString(), 'red bold');

    appendModuleInfo(address);
    addSpace(60);

    const bytes = instruction.address.readByteArray(instruction.size);
    if (bytes) {
        part = ba2hex(bytes);
        append(part, 'yellow');
    } else {
        let _fix = '';
        for (let i=0;i<instruction.size;i++) {
            _fix += '00';
        }
        append(_fix, 'yellow');
    }

    addSpace(70);

    append(instruction.mnemonic, 'green bold');

    addSpace(80);
    spaceAtOpStr = line.length;
    append(instruction.opStr, 'filter');

    if (isJumpInstruction(instruction)) {
        try {
            let jumpInsn = getJumpInstruction(instruction, anyCtx);
            if (jumpInsn) {
                appendModuleInfo(jumpInsn.address);
            }
        } catch (e) {}
    }

    if (typeof annotation !== 'undefined' && annotation !== '') {
        addSpace(90);

        append('@' + annotation, 'pink');
    }

    if (details) {
        part = formatInstructionDetails(spaceAtOpStr, context, instruction, colored, treeSpace);
        if (part.length > 0) {
            append('\n' + part, null);
        }
    }

    if (colored) {
        return coloredLine;
    }
    return line;
}

function formatInstructionDetails(
    spaceAtOpStr: number,
    context: PortableCpuContext,
    instruction: Instruction,
    colored: boolean,
    treeSpace: number): string {
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
                        data.push([reg, value, getTelescope(value,
                            isJumpInstruction(instruction))]);
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
    const _applyColor = function(what: string, color: string | null): string {
        if (colored && color) {
            what = colorify(what, color);
        }
        return what;
    };

    data.forEach(row => {
        if (lines.length > 0) {
            lines[lines.length - 1] += '\n';
        }
        let line = getSpacer(spaceAtOpStr);
        line += _applyColor(row[0], 'blue') + ' = ' + _applyColor(row[1], 'filter');
        if (row.length > 2 && row[2] !== null) {
            let part: string = row[2];
            if (part.length > 0) {
                line += ' >> ' + row[2];
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

function getTelescope(address: NativePointer, isJumpInstruction: boolean): string {
    if (isJumpInstruction) {
        try {
            const instruction = Instruction.parse(address);
            let ret = colorify(instruction.mnemonic, 'green');
            return ret + ')';
        } catch (e) {
            return "";
        }
    } else {
        try {
            let asLong = address.readU64().toNumber();
            let result: string;
            if (asLong < 0x10000) {
                result = colorify('0x' + asLong, 'cyan bold')
            } else {
                result = colorify('0x' + address.readULong().toString(16), 'red');
                try {
                    let str = address.readUtf8String();
                    if (str && str.length > 0) {
                        result += ' (' + colorify(str.replace('\n', ' '), 'green bold') + ')'
                    }
                } catch (e) {}
            }
            return result
        } catch (e) {
            return "";
        }
    }
}

function getJumpInstruction(instruction: Instruction, context: AnyCpuContext): Instruction | null {
    let insn: Arm64Instruction | X86Instruction | null = null;
    if (Process.arch === 'arm64') {
        insn = instruction as Arm64Instruction;
    } else if (Process.arch === 'ia32' || Process.arch === 'x64') {
        insn = instruction as X86Instruction;
    }
    if (insn) {
        if (isJumpInstruction(instruction)) {
            const lastOp = insn.operands[insn.operands.length - 1];
            switch (lastOp.type) {
                case "reg":
                    return Instruction.parse(context[lastOp.value]);
                case "imm":
                    return Instruction.parse(ptr(lastOp.value.toString()))
            }
        }
    }
    return null;
}

function getSpacer(space: number): string {
    let line = '';
    for (let i=0;i<space;i++) {
        line += ' ';
    }
    return line;
}

function isCallInstruction(instruction: Instruction) {
    return callMnemonics.indexOf(instruction.mnemonic) >= 0;
}

function isJumpInstruction(instruction: Instruction): boolean {
    return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
}

function isRetInstruction(instuction: Instruction) {
    return instuction.groups.indexOf('return') >= 0;
}

function onHitInstruction(context: PortableCpuContext, address: NativePointer): void {
    address = address || context.pc;

    const instruction: Instruction = Instruction.parse(address);
    const treeTraceLength = treeTrace.length;

    if (onInstructionCallback !== null) {
        if (treeTraceLength > 0) {
            if (instruction.address.compare(treeTrace[treeTraceLength - 1]) === 0) {
                treeTrace.pop();
            }
        }

        const ctx: HooahContext = {
            context: context,
            instruction: instruction,
            print(params: HooahPrintOptions): void {
                let { details = false, colored = false, annotation = "", treeSpaces = 0 } = params;

                if (treeSpaces > 0 && treeSpaces < 4) {
                    treeSpaces = 4;
                }

                if (instruction) {
                    let line = formatInstruction(
                        context, address, instruction, details, annotation, colored, treeSpaces);
                    if (isJumpInstruction(instruction) || isRetInstruction(instruction)) {
                        line += '\n';
                        if (details) {
                            line += '\n\n';
                        }
                    }
                    console.log(line);
                }
            }
        };

        onInstructionCallback.apply({}, [ctx]);

        if (isCallInstruction(instruction)) {
            treeTrace.push(instruction.next);
        }
    }
}
