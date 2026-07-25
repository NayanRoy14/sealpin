export const ExitCode = {
  Clean: 0,
  Findings: 1,
  Drift: 2,
  Error: 3,
} as const;

export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];
