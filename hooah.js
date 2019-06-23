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
function __HooahTrace() {
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

    const colorify = function (what, pat) {
        var ret = '';
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
    };

    const regexColor = function(text) {
        text = text.toString();
        //text = text.replace(/(\W)([a-z]{1,2}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'cyan') + "$3");
        text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify("$1", 'red'));
        return text;
    };

    this.tid = 0;
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

    this._getTelescope = function (address, isJumpInstruction) {
        var range = Process.findRangeByAddress(address);
        if (range !== null) {
            if (isJumpInstruction) {
                try {
                    const instruction = Instruction.parse(address);
                    var ret = colorify(instruction.mnemonic, 'green') + ' ' + regexColor(instruction.opStr);
                    ret += _getSpacer(2) + '(';
                    if (typeof range.file !== 'undefined' && range.file !== null) {
                        var parts = range.file.path.split('/');
                        ret += parts[parts.length - 1];
                    }
                    ret += '#' + address.sub(range.base);
                    return ret + ')';
                } catch (e) {
                    return null;
                }
            } else {
                try {
                    return address.readUtf8String();
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

    this._formatInstruction = function (address, instruction) {
        var line = colorify(address.toString(), 'red');
        line += _getSpacer(4);
        line += colorify(_ba2hex(address.readByteArray(instruction.size)), 'yellow');
        line += _getSpacer(50 - line.length);
        line += colorify(instruction.mnemonic, 'green');
        line += _getSpacer(70 - line.length);
        line += regexColor(instruction.opStr);
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
                        data.push([reg, value, HooahTrace._getTelescope(value,
                            HooahTrace._isJumpInstruction(instruction))]);
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

        if (HooahTrace.callback !== null && context !== null) {
            HooahTrace.callback.apply({
                context: context,
                instruction: instruction,
                print: function (details) {
                    details = details || false;
                    console.log(HooahTrace._formatInstruction(address, instruction));
                    if (details) {
                        console.log(HooahTrace._formatInstructionDetails(instruction, context))
                    }
                    if (HooahTrace._isJumpInstruction(instruction)) {
                        console.log('');
                    }
                }
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

        // parse options
        args = args || null;
        const callback = HooahTrace._getArg(args, 'callback');
        const count = HooahTrace._getArg(args, 'count', -1);
        const rangeOnly = HooahTrace._getArg(args, 'rangeOnly', false);
        const excludedModules = HooahTrace._getArg(args, 'excludedModules', []);

        const interceptor = Interceptor.attach(target, function () {
            interceptor.detach();
            if (HooahTrace.tid > 0) {
                console.log('Hooah is already tracing thread: ' + HooahTrace.tid);
                return;
            }

            HooahTrace.tid = Process.getCurrentThreadId();
            HooahTrace.callback = callback;

            const startPc = this.context.pc;
            const startRange = Process.findRangeByAddress(target);
            var currentRange = startRange;

            var inTrampoline = true;
            var instructionsCount = 0;

            Stalker.follow(HooahTrace.tid, {
                transform: function (iterator) {
                    var instruction;
                    var range;

                    var skipWholeBlock = false;

                    while ((instruction = iterator.next()) !== null) {
                        if (skipWholeBlock) {
                            continue;
                        }

                        if (inTrampoline) {
                            const testAddress = parseInt(instruction.address.sub(startPc));
                            if (testAddress > 0 && testAddress < 0x30) {
                                inTrampoline = false;
                            }
                        }

                        if (!inTrampoline) {
                            if (typeof range === 'undefined') {
                                range = Process.findRangeByAddress(instruction.address);
                            }

                            if (range !== null) {
                                if (rangeOnly) {
                                    if (parseInt(startRange.base.sub(range.base)) !== 0) {
                                        skipWholeBlock = true;
                                        continue;
                                    }
                                } else {
                                    const file = range.file;
                                    const haveFile = typeof file !== 'undefined' && file !== null;
                                    if (excludedModules.length > 0) {
                                        if (haveFile) {
                                            var filtered = false;
                                            for (var i=0;i<excludedModules.length;i++) {
                                                if (file.path.indexOf(excludedModules[i]) >= 0) {
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

                                    if (parseInt(currentRange.base.sub(range.base)) !== 0) {
                                        currentRange = range;
                                        if (HooahTrace.details) {
                                            var line = 'jumping to range ' + range.base;
                                            if (haveFile) {
                                                line += ' >> ' + range.file.path;
                                            }
                                            console.log(line);
                                        }
                                    }
                                }
                            }

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

                        iterator.keep();
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