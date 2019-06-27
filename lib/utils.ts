export module Utils {
    const callMnemonics = ['call', 'bl', 'blx', 'blr', 'bx'];
    export const insertAt = (str: string, sub: string, pos: number) => `${str.slice(0, pos)}${sub}${str.slice(pos)}`;

    export function ba2hex(b: ArrayBuffer): string {
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

    export function getSpacer(space: number): string {
        return ' '.repeat(space);
    }

    export function isCallInstruction(instruction: Instruction): boolean {
        return callMnemonics.indexOf(instruction.mnemonic) >= 0;
    }

    export function isJumpInstruction(instruction: Instruction): boolean {
        return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
    }

    export function isRetInstruction(instuction: Instruction): boolean {
        return instuction.groups.indexOf('return') >= 0;
    }
}