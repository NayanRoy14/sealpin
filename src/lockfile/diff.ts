import type { Tool, ToolManifest } from '../types/manifest.js';
import { canonicalizeTool } from './canonicalize.js';

export interface ChangedTool {
  name: string;
  before: Tool;
  after: Tool;
}

export interface ManifestDiff {
  server: string;
  addedTools: Tool[];
  removedTools: Tool[];
  changedTools: ChangedTool[];
}

export function diffManifests(before: ToolManifest, after: ToolManifest): ManifestDiff {
  const beforeMap = new Map(before.tools.map((t) => [t.name, t]));
  const afterMap = new Map(after.tools.map((t) => [t.name, t]));

  const addedTools = [...afterMap.values()].filter((t) => !beforeMap.has(t.name));
  const removedTools = [...beforeMap.values()].filter((t) => !afterMap.has(t.name));

  const changedTools: ChangedTool[] = [];
  for (const [name, afterTool] of afterMap) {
    const beforeTool = beforeMap.get(name);
    if (beforeTool && canonicalizeTool(beforeTool) !== canonicalizeTool(afterTool)) {
      changedTools.push({ name, before: beforeTool, after: afterTool });
    }
  }

  return { server: after.server, addedTools, removedTools, changedTools };
}

export function isEmptyDiff(diff: ManifestDiff): boolean {
  return diff.addedTools.length === 0 && diff.removedTools.length === 0 && diff.changedTools.length === 0;
}
