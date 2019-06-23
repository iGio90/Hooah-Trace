function __HooahTrace() {
    this.tid = 0;
    this.verbose = true;
    this.callback = null;
    this.executionBlock = {};
    this.currentContext = {};

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

    this._formatInstruction = function (address, instruction) {
        var line = address.toString();
        line += _getSpacer(4);
        line += _ba2hex(address.readByteArray(instruction.size));
        line += _getSpacer(30 - line.length);
        line += instruction.mnemonic;
        line += _getSpacer(45 - line.length);
        line += instruction.opStr;

        if (HooahTrace._isJumpInstruction(instruction)) {
            line += '\n';
        }
        return line;
    };

    this.onHitInstruction = function (context, address) {
        address = address || context.pc;
        const instruction = HooahTrace.executionBlock[address.toString()];
        HooahTrace.currentContext = context;

        if (typeof instruction === 'undefined') {
            console.log('stalker hit invalid instruction :\'(');
            HooahTrace.detach();
            return;
        }

        if (HooahTrace.verbose) {
            console.log(HooahTrace._formatInstruction(address, instruction));
        }

        if (HooahTrace.callback !== null) {
            if (HooahTrace.verbose)
            HooahTrace.callback.apply({
                context: context,
                instruction: instruction
            });
        }

        delete HooahTrace.executionBlock[address.toString()];
    };

    this.getArg = function (args, key, def) {
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

    this.attach = function (target, args) {
        if (HooahTrace.tid > 0) {
            console.log('Hooah is already tracing thread: ' + HooahTrace.tid);
        }

        if (target === null) {
            console.log('missing target to attach');
            return null;
        }

        args = args || null;
        const callback = HooahTrace.getArg(args, 'callback');
        const count = HooahTrace.getArg(args, 'count', -1);
        HooahTrace.verbose = HooahTrace.getArg(args, 'verbose', true);

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
                            HooahTrace.onHitInstruction(HooahTrace.currentContext, ptr(address))
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