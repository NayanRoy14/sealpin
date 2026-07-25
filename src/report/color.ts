/**
 * Minimal ANSI styling. A security tool shouldn't pull in a color dependency
 * just to bold some text. Honors NO_COLOR and non-TTY output automatically,
 * and can be forced off for --no-color.
 */
let enabled = process.stdout.isTTY === true && !process.env['NO_COLOR'];

export function setColorEnabled(value: boolean): void {
  enabled = value;
}

function wrap(open: number, close: number) {
  return (s: string): string => (enabled ? `[${open}m${s}[${close}m` : s);
}

export const color = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
};
