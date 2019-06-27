import {Color} from "./color";
import {Utils} from "./utils";
import * as OnLoadInterceptor from "frida-onload"

export module HooahTrace {
    interface AnyCpuContext extends PortableCpuContext {
        [name: string]: NativePointer;
    }

    interface HooahPrintOptions {
        colored?: boolean;
        details?: boolean;
        treeSpaces?: number;
    }

    interface HooahOptions {
        printBlocks?: boolean;
        count?: number;
        filterModules?: string[];
        printOptions?: HooahPrintOptions;
    }

    interface PrintInfo {
        data: string;
        lineLength: number;
        details?: PrintInfo[];
    }

    type HooahCallback = (context: CpuContext, instruction: Instruction) => void;

    const treeTrace: NativePointer[] = [];
    let targetTid = 0;
    let onInstructionCallback: HooahCallback | null = null;
    let moduleMap = new ModuleMap();
    let filtersModuleMap: ModuleMap | null = null;

    const currentExecutionBlock: PrintInfo[] = [];
    let currentBlockStartWidth = 0;
    let currentBlockMaxWidth = 0;
    let hitRetInstruction = false;

    let sessionPrintBlocks = true;
    let sessionPrintOptions: HooahPrintOptions;
    let sessionPrevSepCount = 0;

    export function trace(callback: HooahCallback, params: HooahOptions = {}) {
        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return 1;
        }

        const {
            printBlocks = true,
            count = -1,
            filterModules = [],
            printOptions = {}
        } = params;
        sessionPrintBlocks = printBlocks;
        sessionPrintOptions = printOptions;
        if (sessionPrintOptions.treeSpaces && sessionPrintOptions.treeSpaces < 4) {
            sessionPrintOptions.treeSpaces = 4;
        }

        if (targetTid > 0) {
            console.log('Hooah is already tracing thread: ' + targetTid);
            return;
        }

        targetTid = Process.getCurrentThreadId();
        onInstructionCallback = callback;

        moduleMap.update();
        filtersModuleMap = new ModuleMap(module => {
            // do not follow frida agent
            if (module.name.indexOf('frida-agent') >= 0) {
                return true;
            }

            let found = false;
            filterModules.forEach(filter => {
                if (module.name.indexOf(filter) >= 0) {
                    found = true;
                }
            });
            return found;
        });

        OnLoadInterceptor.attach(() => {
            moduleMap.update();
            if (filtersModuleMap) {
                filtersModuleMap.update();
            }
        });

        let instructionsCount = 0;
        let startAddress = NULL;

        Stalker.follow(targetTid, {
            transform: function (iterator: StalkerArm64Iterator | StalkerX86Iterator) {
                let instruction: Arm64Instruction | X86Instruction | null;
                let moduleFilterLocker = false;

                while ((instruction = iterator.next()) !== null) {
                    if (moduleFilterLocker) {
                        iterator.keep();
                        continue;
                    }

                    if (filtersModuleMap && filtersModuleMap.has(instruction.address)) {
                        moduleFilterLocker = true;
                    }

                    if (!moduleFilterLocker) {
                        // basically skip the first block of code (from frida)
                        if (startAddress.compare(NULL) === 0) {
                            startAddress = instruction.address;
                            moduleFilterLocker = true;
                        } else {
                            iterator.putCallout(<(context: PortableCpuContext) => void>onHitInstruction);
                        }
                    }

                    if (count > 0) {
                        instructionsCount++;
                        if (instructionsCount === count) {
                            stop();
                        }
                    }

                    iterator.keep();
                }
            }
        });

        return 0;
    }

    export function stop(): void {
        Stalker.unfollow(targetTid);
        filtersModuleMap = null;
        onInstructionCallback = null;
        treeTrace.length = 0;
        targetTid = 0;

        currentExecutionBlock.length = 0;
        currentBlockMaxWidth = 0;

        sessionPrevSepCount = 0;
    }

    function onHitInstruction(context: PortableCpuContext): void {
        const address = context.pc;
        const instruction: Instruction = Instruction.parse(address);
        const treeTraceLength = treeTrace.length;

        if (onInstructionCallback !== null) {
            if (hitRetInstruction) {
                hitRetInstruction = false;
                if (treeTraceLength > 0) {
                    treeTrace.pop();
                }
            }

            onInstructionCallback.apply({}, [context, instruction]);

            if (sessionPrintBlocks) {
                const { details = false, colored = false, treeSpaces = 4 } = sessionPrintOptions;

                const isCall = Utils.isCallInstruction(instruction);
                const isJump = Utils.isJumpInstruction(instruction);
                const isRet = Utils.isRetInstruction(instruction);

                const line = formatInstruction(context, address, instruction, details, colored, treeSpaces, isJump);
                currentExecutionBlock.push(line);
                if (isJump || isRet) {
                    if (currentExecutionBlock.length > 0) {
                        blockifyBlock(details);
                    }
                    currentExecutionBlock.length = 0;
                    currentBlockMaxWidth = 0;
                }

                if (isCall) {
                    treeTrace.push(instruction.next);
                } else if (isRet) {
                    hitRetInstruction = true;
                }
            }
        }
    }

    function blockifyBlock(details: boolean): void {
        const divMod = currentBlockMaxWidth % 8;
        if (divMod !== 0) {
            currentBlockMaxWidth -= divMod;
            currentBlockMaxWidth += 8;
        }
        const realLineWidth = currentBlockMaxWidth - currentBlockStartWidth;
        const startSpacer = Utils.getSpacer(currentBlockStartWidth + 1);
        let sepCount = (realLineWidth + 8) / 4;
        const topSep = ' _'.repeat(sepCount).substring(1);
        const botSep = ' \u00AF'.repeat(sepCount).substring(1);
        const nextSepCount = currentBlockStartWidth + 1 + botSep.length;
        const emptyLine = formatLine({data: ' '.repeat(currentBlockMaxWidth), lineLength: currentBlockMaxWidth});
        let topMid = ' ';
        if (sessionPrevSepCount > 0) {
            topMid = '|';
            const sepDiff  = sessionPrevSepCount - nextSepCount;
            if (sepDiff < 0) {
                const spacer = Utils.getSpacer(sessionPrevSepCount);
                if (details) {
                    console.log(spacer + '|');
                }
                console.log(spacer + '|' + '_ '.repeat(-sepDiff / 2));
                console.log(spacer + Utils.getSpacer(-sepDiff) + '|')
            } else if (sepDiff > 0) {
                const spacer = Utils.getSpacer(nextSepCount);
                console.log(spacer + '|' + '\u00AF '.repeat(sepDiff / 2));
                if (details) {
                    console.log(spacer + '|');
                }
            }
        }
        console.log(startSpacer + topSep + topMid + topSep);
        currentExecutionBlock.forEach(printInfo => {
            console.log(emptyLine);
            if (printInfo.details) {
                printInfo.details.forEach(detailPrintInfo => {
                    console.log(formatLine(detailPrintInfo));
                });
            }
            console.log(formatLine(printInfo));
            console.log(emptyLine);
        });
        console.log(startSpacer + botSep + '|' + botSep);
        sessionPrevSepCount = nextSepCount;
        console.log(Utils.getSpacer(sessionPrevSepCount) + '|');
        if (details) {
            console.log(Utils.getSpacer(sessionPrevSepCount) + '|');
        }
    }

    function formatLine(printInfo: PrintInfo) {
        let toPrint = printInfo.data;
        toPrint = Utils.insertAt(toPrint, '|    ', currentBlockStartWidth);
        toPrint += Utils.getSpacer(currentBlockMaxWidth - printInfo.lineLength);
        toPrint += '    |';
        return toPrint;
    }

    function formatInstruction(
        context: PortableCpuContext,
        address: NativePointer,
        instruction: Instruction,
        details: boolean,
        colored: boolean,
        treeSpaces: number,
        isJump: boolean): PrintInfo {

        const anyCtx = context as AnyCpuContext;
        let line = "";
        let coloredLine = "";
        let part: string;
        let intTreeSpace = 0;
        let spaceAtOpStr: number;

        const append = function(what: string, color?: string): void {
            line += what;
            if (colored) {
                if (color) {
                    coloredLine += Color.colorify(what, color);
                } else {
                    coloredLine += what;
                }
            }
        };

        const appendModuleInfo = function(address: NativePointer): void {
            const module = moduleMap.find(address);
            if (module !== null) {
                append(' (');
                append(module.name, 'green bold');
                part = '#';
                append(part);
                part = address.sub(module.base).toString();
                append(part, 'red');
                part = ')';
                append(part);
            }
        };

        const addSpace = function(count: number): void {
            append(Utils.getSpacer(count + intTreeSpace - line.length));
        };

        if (treeSpaces > 0 && treeTrace.length > 0) {
            intTreeSpace = (treeTrace.length) * treeSpaces;
            append(Utils.getSpacer(intTreeSpace));
        }

        currentBlockStartWidth = line.length;
        append(address.toString(), 'red bold');

        appendModuleInfo(address);
        addSpace(40);

        const bytes = instruction.address.readByteArray(instruction.size);
        if (bytes) {
            part = Utils.ba2hex(bytes);
            append(part, 'yellow');
        } else {
            let _fix = '';
            for (let i=0;i<instruction.size;i++) {
                _fix += '00';
            }
            append(_fix, 'yellow');
        }

        addSpace(50);

        append(instruction.mnemonic, 'green bold');

        addSpace(60);
        spaceAtOpStr = line.length;
        append(instruction.opStr, 'filter');

        if (isJump) {
            try {
                let jumpInsn = getJumpInstruction(instruction, anyCtx);
                if (jumpInsn) {
                    appendModuleInfo(jumpInsn.address);
                }
            } catch (e) {}
        }

        const lineLength = line.length;
        if (lineLength > currentBlockMaxWidth) {
            currentBlockMaxWidth = lineLength;
        }

        let detailsData: PrintInfo[] = [];
        if (details) {
            detailsData = formatInstructionDetails(spaceAtOpStr, context, instruction, colored, isJump);
            detailsData.forEach(detail => {
                if (detail.lineLength > currentBlockMaxWidth) {
                    currentBlockMaxWidth = detail.lineLength;
                }
            });
        }

        return {data: colored ? coloredLine : line, lineLength: lineLength, details: detailsData};
    }

    function formatInstructionDetails(
        spaceAtOpStr: number,
        context: PortableCpuContext,
        instruction: Instruction,
        colored: boolean,
        isJump: boolean): PrintInfo[] {
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
                }

                if (typeof reg !== 'undefined' && !visited.has(reg)) {
                    visited.add(reg);
                    try {
                        value = anyContext[reg];
                        if (typeof value !== 'undefined') {
                            value = anyContext[reg].add(adds);
                            data.push([reg, value, getTelescope(value, isJump)]);
                        } else {
                            //data.push([reg, 'register not found in context']);
                        }
                    } catch (e) {
                        //data.push([reg, 'register not found in context']);
                    }
                }
            });
        }

        const applyColor = function(what: string, color: string | null): string {
            if (colored && color) {
                what = Color.colorify(what, color);
            }
            return what;
        };

        let lines: PrintInfo[] = [];
        data.forEach(row => {
            let line = Utils.getSpacer(spaceAtOpStr);
            let lineLength = spaceAtOpStr + row[0].length + row[1].toString().length + 3;
            line += applyColor(row[0], 'blue') + ' = ' + applyColor(row[1], 'filter');
            if (row.length > 2 && row[2] !== null) {
                const printInfo = row[2] as PrintInfo;
                if (printInfo.lineLength > 0) {
                    line += ' >> ' + printInfo.data;
                    lineLength += printInfo.lineLength + 4;
                }
            }
            lines.push({data: line, lineLength: lineLength});
        });
        return lines;
    }

    function getTelescope(address: NativePointer, isJump: boolean): PrintInfo {
        if (isJump) {
            try {
                const instruction = Instruction.parse(address);
                let ret = Color.colorify(instruction.mnemonic, 'green');
                ret += ' ' + instruction.opStr;
                return {data: ret, lineLength: instruction.mnemonic.length + instruction.opStr.length + 1};
            } catch (e) {}
        } else {
            let count = 0;
            let current = address;
            let result: string = "";
            let resLen = 0;
            while (true) {
                try {
                    current = current.readPointer();
                    const asStr = current.toString();
                    if (result.length > 0) {
                        result += ' >> ';
                        resLen += 4;
                    }
                    resLen += asStr.length;
                    if (current.compare(0x10000) < 0) {
                        result += Color.colorify(asStr, 'cyan bold');
                        break;
                    } else {
                        result += Color.colorify(asStr, 'red');

                        try {
                            let str = address.readUtf8String();
                            if (str && str.length > 0) {
                                result += ' (' + Color.colorify(str.replace('\n', ' '),'green bold') + ')';
                                resLen += str.length + 3;
                            }
                        } catch (e) {}
                    }
                    if (count === 5) {
                        break;
                    }
                    count += 1;
                } catch (e) {
                    break;
                }
            }
            return {data: result, lineLength: resLen};
        }

        return {data: '', lineLength: 0};
    }

    function getJumpInstruction(instruction: Instruction, context: AnyCpuContext): Instruction | null {
        let insn: Arm64Instruction | X86Instruction | null = null;
        if (Process.arch === 'arm64') {
            insn = instruction as Arm64Instruction;
        } else if (Process.arch === 'ia32' || Process.arch === 'x64') {
            insn = instruction as X86Instruction;
        }
        if (insn) {
            if (Utils.isJumpInstruction(instruction)) {
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
}
