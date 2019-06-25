import * as OnLoadInterceptor from "frida-onload"


interface AnyCpuContext extends PortableCpuContext {
    [name: string]: NativePointer;
}

export interface HooahPrintOptions {
    colored?: boolean | undefined;
    details?: boolean | undefined;
    annotation?: string | undefined;
    treeSpace?: number | undefined;
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

const executionBlockAddresses = new Set<string>();
const treeTrace: NativePointer[] = [];
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
                let skipWholeBlock = false;
                let blockEnter = true;

                while ((instruction = iterator.next()) !== null) {
                    if (skipWholeBlock) {
                        continue;
                    }

                    if (inTrampoline) {
                        const testAddress = instruction.address.sub(startPc).compare(0x30);
                        if (testAddress < 0) {
                            inTrampoline = false;
                        }
                    }

                    if (!inTrampoline) {
                        if (filtersModuleMap && filtersModuleMap.has(instruction.address)) {
                            skipWholeBlock = true;
                            continue;
                        }

                        if (blockEnter) {
                            let treeLength = treeTrace.length;
                            if (treeTrace.length > 0) {
                                if (instruction.address.compare(treeLength - 1) == 0) {
                                    treeTrace.pop();
                                } else {
                                    treeTrace.push(ptr(instruction.address.toString()));
                                }
                            } else {
                                treeTrace.push(ptr(instruction.address.toString()));
                            }
                        }

                        executionBlockAddresses.add(instruction.address.toString());
                        iterator.putCallout(<(context: PortableCpuContext) => void>onHitInstruction);

                        if (count > 0) {
                            instructionsCount++;
                            if (instructionsCount === count) {
                                detach();
                            }
                        }
                    }

                    if (blockEnter) {
                        blockEnter = false;
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
    targetTid = 0;
}

function applyColorFilters(text: string): string {
    text = text.toString();
    //text = text.replace(/(\W)([a-z]{1,2}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'blue') + "$3");
    text = text.replace(/(\W|^)([a-z]{1,3}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'blue') + "$3");
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
        ret += _bold + ' ';
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

    let line = "";
    let coloredLine = "";
    let part: string;

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

    const appendModuleInfo = function(address: NativePointer): void{
        const module = moduleMap.find(address);
        if (module !== null) {
            append(' (', null);
            append(module.name, 'green');
            part = '#';
            append(part, null);
            part = address.sub(module.base).toString();
            append(part, 'red');
            part = ')';
            append(part, null);
        }
    };

    if (treeSpace > 0 && treeTrace.length > 0) {
        append(getSpacer((treeTrace.length - 1) * treeSpace), null);
    }

    append(address.toString(), 'red bold');

    appendModuleInfo(address);
    append(getSpacer(60 - line.length), null);

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

    append(getSpacer(70 - line.length), null);

    append(instruction.mnemonic, 'green bold');

    append(getSpacer(80 - line.length), null);

    append(instruction.opStr, 'filter');

    if (isJumpInstruction(instruction)) {
        appendModuleInfo(instruction.address)
    }

    if (typeof annotation !== 'undefined' && annotation !== '') {
        append(getSpacer(90 - line.length), null);

        append('@' + annotation, 'pink');
    }

    if (details) {
        part = formatInstructionDetails(context, instruction, colored, treeSpace);
    }

    if (colored) {
        return coloredLine;
    }
    return line;
}

function formatInstructionDetails(
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
    let spacer = getSpacer((instruction.address.toString().length / 2));
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
        let line = "";
        if (treeTrace.length > 0) {
            line += getSpacer((treeTrace.length - 1) * treeSpace);
        }
        line += spacer + '|------------------------>' + spacer;
        line += _applyColor(row[0], 'blue bold') + ' = ' + _applyColor(row[1], 'filter');
        if (row.length > 2 && row[2] !== null) {
            if (row[2].length === 0) {
                line += ' >> ' + _applyColor('0x0', 'red');
            } else {
                line += ' >> ' + _applyColor(row[2], 'filter');
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

function getTelescope(address: NativePointer, isJumpInstruction: boolean) {
    let telescope;
    try {
        telescope = address.readPointer();
    } catch (e) {
        return null;
    }

    if (isJumpInstruction) {
        try {
            const instruction = Instruction.parse(address);
            let ret = colorify(instruction.mnemonic, 'green') + ' ' + applyColorFilters(instruction.opStr);
            ret += getSpacer(2) + '(';
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
            return telescope;
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

function isJumpInstruction(instruction: Instruction): boolean {
    return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
}

function onHitInstruction(context: PortableCpuContext, address: NativePointer): void {
    address = address || context.pc;

    if (!executionBlockAddresses.has(address.toString())) {
        console.log('stalker hit invalid instruction :\'(');
        detach();
        return;
    }

    const instruction: Instruction = Instruction.parse(address);

    if (onInstructionCallback !== null) {
        const ctx: HooahContext = {
            context: context,
            instruction: instruction,
            print(params: HooahPrintOptions): void {
                const { details = false, colored = false, annotation = "", treeSpace = 0 } = params;

                if (instruction) {
                    let line = formatInstruction(
                        context, address, instruction, details, annotation, colored, treeSpace);
                    if (isJumpInstruction(instruction)) {
                        line += '\n'
                    }
                    console.log(line);
                }
            }
        };

        onInstructionCallback.apply({}, [ctx]);
    }

    executionBlockAddresses.delete(address.toString());
}

function uncoloredStringLength(text: string): number {
    return text.replace(/\x1b\[(0;)?\d+m/gm, "").length;
}