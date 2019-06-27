export module Color {
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

    export function applyColorFilters(text: string): string {
        text = text.toString();
        text = text.replace(/(\W|^)([a-z]{1,4}\d{0,2})(\W|$)/gm, "$1" + colorify("$2", 'blue') + "$3");
        text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify("$1", 'red'));
        text = text.replace(/#(\d+)/gm, "#" + colorify("$1", 'red'));
        return text;
    }

    export function colorify(what: string, pat:string): string {
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
}