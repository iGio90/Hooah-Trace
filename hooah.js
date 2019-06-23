function __HooahTrace() {
    this.tracing = false;
    this.callback = null;

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

    this.onHitInstruction = function (context) {
        const instruction = Instruction.parse(context.pc);

        var line = instruction.address;
        line += _getSpacer(4);
        line += _ba2hex(context.pc.readByteArray(instruction.size));
        line += _getSpacer(30 - line.length);
        line += instruction.mnemonic;
        line += _getSpacer(45 - line.length);
        line += instruction.opStr;

        if (instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0) {
            line += '\n';
        }

        if (HooahTrace.callback !== null) {
            const that = {
                context: context,
                instruction: instruction,
                print: function () {
                    console.log(line);
                }
            };
            HooahTrace.callback.apply(that);
        } else {
            console.log(line);
        }
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
        if (this.tracing) {
            console.log('tracer already running');
        }

        if (target === null) {
            console.log('missing target to attach');
            return null;
        }

        args = args || null;
        const callback = HooahTrace.getArg(args, 'callback');
        const count = HooahTrace.getArg(args, 'count', -1);

        const interceptor = Interceptor.attach(target, function () {
            interceptor.detach();
            if (HooahTrace.tracing) {
                console.log('Hooah is already tracing another thread');
                return;
            }

            HooahTrace.tracing = true;
            HooahTrace.callback = callback;

            const tid = Process.getCurrentThreadId();
            const pc = this.context.pc;

            var inTrampoline = true;
            var instructionsCount = 0;

            Stalker.follow(tid, {
                transform: function (iterator) {
                    var instruction;
                    while ((instruction = iterator.next()) !== null) {
                        iterator.keep();

                        if (inTrampoline) {
                            const testAddress = parseInt(instruction.address.sub(pc));
                            if (testAddress > 0 && testAddress < 0x30) {
                                inTrampoline = false;
                            }
                        }

                        if (!inTrampoline) {
                            iterator.putCallout(HooahTrace.onHitInstruction);
                            if (count > 0) {
                                instructionsCount++;
                                if (instructionsCount === count) {
                                    Stalker.unfollow(tid);
                                }
                            }
                        }
                    }
                }
            });
        });
    };

    return this;
}

const HooahTrace = new __HooahTrace();
module.exports = HooahTrace;