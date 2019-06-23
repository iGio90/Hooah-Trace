function __HooahTrace() {
    this.tid = 0;
    this.verbose = true;
    this.details = true;
    this.callback = null;
    this.executionBlock = {};

    const _getSpacer = function (space) {
        var line = '';
        for (var i=0;i<space;i++) {
            line += ' ';
        }
        return line;
    };

    const _ba2hex = function (b) {
        var uint8arr = new Uint8Array(b);
        if (!uint8arr) {
            return '';
        }
        var hexStr = '';
        for (var i = 0; i < uint8arr.length; i++) {
            var hex = (uint8arr[i] & 0xff).toString(16);
            hex = (hex.length === 1) ? '0' + hex : hex;
            hexStr += hex;
        }
        return hexStr;
    };

    this._isJumpInstruction = function (instruction) {
        return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
    };

    this._getArg = function (args, key, def) {
        def = def || null;
        if (args === null) {
            return def;
        }
        var arg = args[key];
        if (typeof arg === 'undefined') {
            arg = def;
        }
        return arg;
    };

    this._getTelescope = function (address) {
        var range = Process.findRangeByAddress(address);
        if (range !== null) {
            try {
                return address.readUtf8String();
            } catch (e) {
                try {
                    address = address.readPointer();
                    return address;
                } catch (e) {}
            }
        }
        return null;
    };

    this._formatInstruction = function (address, instruction) {
        var line = address.toString();
        line += _getSpacer(4);
        line += _ba2hex(address.readByteArray(instruction.size));
        line += _getSpacer(30 - line.length);
        line += instruction.mnemonic;
        line += _getSpacer(45 - line.length);
        line += instruction.opStr;
        return line;
    };

    this._formatInstructionDetails = function (instruction, context) {
        const data = [];
        const visited = [];
        instruction.operands.forEach(function (op) {
            var reg = null;
            var value = null;
            var adds = 0;
            if (op.type === 'mem') {
                reg = op.value.base;
                adds = op.value.disp;
            } else if (op.type === 'reg') {
                reg = op.value;
            } else if (op.type === 'imm') {
                if (data.length > 0) {
                    value = data[data.length - 1][1];
                    if (value.constructor.name === 'NativePointer') {
                        data[data.length - 1][1].add(parseInt(op.value));
                    }
                }
            }

            if (reg !== null && visited.indexOf(reg) === -1) {
                visited.push(reg);
                try {
                    value = context[reg];
                    if (typeof value !== 'undefined') {
                        value = context[reg].add(adds);
                        data.push([reg, value, HooahTrace._getTelescope(value)]);
                    } else {
                        //data.push([reg, 'register not found in context']);
                    }
                } catch (e) {
                    //data.push([reg, 'register not found in context']);
                }
            }
        });
        var lines = [];
        var spacer = _getSpacer((instruction.address.toString().length / 2) - 1);
        data.forEach(function (row) {
            if (lines.length > 0) {
                lines[lines.length - 1] += '\n';
            }
            var line = spacer + '|---------' + spacer;
            line += row[0] + ' = ' + row[1];
            if (row.length > 2 && row[2] !== null) {
                if (row[2].length === 0) {
                    line += ' >> 0x0';
                } else {
                    line += ' >> ' + row[2];
                }
            }
            lines.push(line);
        });

        var ret = '';
        lines.forEach(function (line) {
           ret += line;
        });
        return ret;
    };

    this.onHitInstruction = function (context, address) {
        address = address || context.pc;
        const instruction = HooahTrace.executionBlock[address.toString()];

        if (typeof instruction === 'undefined') {
            console.log('stalker hit invalid instruction :\'(');
            HooahTrace.detach();
            return;
        }

        if (HooahTrace.verbose) {
            console.log(HooahTrace._formatInstruction(address, instruction));
            if (HooahTrace.details) {
                console.log(HooahTrace._formatInstructionDetails(instruction, context))
            }
            if (HooahTrace._isJumpInstruction(instruction)) {
                console.log('');
            }
        }

        if (HooahTrace.callback !== null && context !== null) {
            HooahTrace.callback.apply({
                context: context,
                instruction: instruction
            });
        }

        delete HooahTrace.executionBlock[address.toString()];
    };

    this.attach = function (target, args) {
        if (HooahTrace.tid > 0) {
            console.log('Hooah is already tracing thread: ' + HooahTrace.tid);
        }

        if (target === null) {
            console.log('missing target to attach');
            return null;
        }

        args = args || null;
        const callback = HooahTrace._getArg(args, 'callback');
        const count = HooahTrace._getArg(args, 'count', -1);
        HooahTrace.verbose = HooahTrace._getArg(args, 'verbose', true);
        HooahTrace.details = HooahTrace._getArg(args, 'details', false);

        const interceptor = Interceptor.attach(target, function () {
            interceptor.detach();
            if (HooahTrace.tid > 0) {
                console.log('Hooah is already tracing thread: ' + HooahTrace.tid);
                return;
            }

            HooahTrace.tid = Process.getCurrentThreadId();
            HooahTrace.callback = callback;

            const pc = this.context.pc;

            var inTrampoline = true;
            var instructionsCount = 0;

            Stalker.follow(HooahTrace.tid, {
                transform: function (iterator) {
                    var instruction;

                    if (HooahTrace.verbose && Object.keys(HooahTrace.executionBlock).length > 0) {
                        Object.keys(HooahTrace.executionBlock).forEach(function (address) {
                            HooahTrace.onHitInstruction(null, ptr(address))
                        })
                    }

                    while ((instruction = iterator.next()) !== null) {
                        iterator.keep();

                        if (inTrampoline) {
                            const testAddress = parseInt(instruction.address.sub(pc));
                            if (testAddress > 0 && testAddress < 0x30) {
                                inTrampoline = false;
                            }
                        }

                        if (!inTrampoline) {
                            HooahTrace.executionBlock[instruction.address.toString()] = new function () {
                                this.address = instruction.address;
                                this.mnemonic = instruction.mnemonic;
                                this.opStr = instruction.opStr;
                                this.groups = instruction.groups;
                                this.operands = instruction.operands;
                                this.size = instruction.size;
                            };
                            iterator.putCallout(HooahTrace.onHitInstruction);

                            if (count > 0) {
                                instructionsCount++;
                                if (instructionsCount === count) {
                                    HooahTrace.detach();
                                }
                            }
                        }
                    }
                }
            });
        });
    };

    this.detach = function () {
        Stalker.unfollow(HooahTrace.tid);
        HooahTrace.tid = 0;
    };

    return this;
}

const HooahTrace = new __HooahTrace();
module.exports = HooahTrace;