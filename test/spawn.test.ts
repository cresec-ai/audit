import { describe, expect, it } from 'vitest';

import { planSpawn, resolveCommand } from '../src/proxy/spawn.js';
import type { FsProbe } from '../src/proxy/spawn.js';

/**
 * A pure in-memory fs stub: `files` is the exact set of paths that "exist"
 * (and are files). Lets resolveCommand/planSpawn be exercised deterministically
 * for win32 on any host OS, including this suite's own (Linux/macOS) CI.
 */
function fakeFs(files: Iterable<string>): FsProbe {
  // Case-insensitive, like the real Windows filesystem this stands in for
  // (PATHEXT candidates are generated in the extension's own casing, e.g.
  // the default list's ".EXE", regardless of how a test spells its fixture
  // paths).
  const set = new Set(Array.from(files, (f) => f.toLowerCase()));
  return {
    existsSync: (p) => set.has(p.toLowerCase()),
    statSync: (p) => ({ isFile: () => set.has(p.toLowerCase()) }),
  };
}

const throwingFs: FsProbe = {
  existsSync: () => {
    throw new Error('existsSync must not be called on non-win32');
  },
  statSync: () => {
    throw new Error('statSync must not be called on non-win32');
  },
};

describe('resolveCommand', () => {
  it('is the identity on non-win32 platforms and never touches the fs', () => {
    expect(resolveCommand('npx', { PATH: '/usr/bin' }, 'linux', throwingFs)).toBe('npx');
    expect(resolveCommand('/usr/bin/node', {}, 'darwin', throwingFs)).toBe('/usr/bin/node');
  });

  it('searches PATH (;-delimited) for a bare command using default PATHEXT order (.COM, .EXE, .BAT, .CMD)', () => {
    const env = { PATH: 'C:\\first;C:\\second' };
    const fs = fakeFs(['C:\\second\\npx.cmd']);
    // The candidate tried is built from PATHEXT's own casing (.CMD); disk
    // lookups are case-insensitive on Windows, so this still finds the
    // lowercase-suffixed fixture and is exactly what gets spawned.
    expect(resolveCommand('npx', env, 'win32', fs)).toBe('C:\\second\\npx.CMD');
  });

  it('prefers an earlier PATHEXT extension over a later one when both exist', () => {
    const env = { PATH: 'C:\\tools' };
    const fs = fakeFs(['C:\\tools\\npx.exe', 'C:\\tools\\npx.cmd']);
    // default order .COM;.EXE;.BAT;.CMD -> .exe wins over .cmd
    expect(resolveCommand('npx', env, 'win32', fs)).toBe('C:\\tools\\npx.EXE');
  });

  it('honours a custom PATHEXT order from the environment', () => {
    const env = { PATH: 'C:\\tools', PATHEXT: '.CMD;.EXE' };
    const fs = fakeFs(['C:\\tools\\npx.exe', 'C:\\tools\\npx.cmd']);
    expect(resolveCommand('npx', env, 'win32', fs)).toBe('C:\\tools\\npx.CMD');
  });

  it('searches every PATH entry in order, not just the first', () => {
    const env = { PATH: 'C:\\empty;C:\\also-empty;C:\\real' };
    const fs = fakeFs(['C:\\real\\uvx.exe']);
    expect(resolveCommand('uvx', env, 'win32', fs)).toBe('C:\\real\\uvx.EXE');
  });

  it('honours an explicit extension on the command instead of appending more PATHEXT extensions', () => {
    const env = { PATH: 'C:\\tools' };
    // Only the exact "npx.cmd" exists; if resolveCommand ignored the
    // explicit extension and tried appending PATHEXT extensions to it
    // (e.g. "npx.cmd.EXE"), nothing here would ever match it anyway — the
    // real assertion is that the exact, already-extensioned path resolves.
    const fs = fakeFs(['C:\\tools\\npx.cmd']);
    expect(resolveCommand('npx.cmd', env, 'win32', fs)).toBe('C:\\tools\\npx.cmd');
  });

  it('is case-insensitive when matching an explicit extension against PATHEXT', () => {
    const env = { PATH: 'C:\\tools' };
    const fs = fakeFs(['C:\\tools\\npx.Cmd']);
    expect(resolveCommand('npx.Cmd', env, 'win32', fs)).toBe('C:\\tools\\npx.Cmd');
  });

  it('resolves a command with a directory component directly, without searching PATH', () => {
    const env = { PATH: 'C:\\unrelated' };
    const fs = fakeFs(['.\\tools\\myserver.cmd', 'C:\\unrelated\\myserver.cmd']);
    // A decoy of the same basename sits on PATH; the directory component
    // must make resolution ignore PATH entirely and resolve the given path.
    expect(resolveCommand('.\\tools\\myserver.cmd', env, 'win32', fs)).toBe('.\\tools\\myserver.cmd');
  });

  it('appends PATHEXT extensions to a directory-qualified command with no extension of its own', () => {
    const env = { PATH: '' };
    const fs = fakeFs(['C:\\srv\\myserver.exe']);
    expect(resolveCommand('C:\\srv\\myserver', env, 'win32', fs)).toBe('C:\\srv\\myserver.EXE');
  });

  it('falls back to the original string when nothing on PATH matches', () => {
    const env = { PATH: 'C:\\tools' };
    const fs = fakeFs([]);
    expect(resolveCommand('does-not-exist', env, 'win32', fs)).toBe('does-not-exist');
  });

  it('falls back to the original string for an unresolvable directory-qualified command', () => {
    const env = { PATH: 'C:\\tools' };
    const fs = fakeFs([]);
    expect(resolveCommand('C:\\nope\\missing.cmd', env, 'win32', fs)).toBe('C:\\nope\\missing.cmd');
  });

  it('uses the default PATHEXT list (.COM;.EXE;.BAT;.CMD) when PATHEXT is unset', () => {
    const env = { PATH: 'C:\\tools' }; // no PATHEXT key at all
    const fs = fakeFs(['C:\\tools\\legacy.bat']);
    expect(resolveCommand('legacy', env, 'win32', fs)).toBe('C:\\tools\\legacy.BAT');
  });
});

describe('planSpawn', () => {
  it('is an identity plan on non-win32: no options, args and file unchanged', () => {
    const plan = planSpawn(['/usr/bin/node', '--version', 'x'], { PATH: '/usr/bin' }, 'linux');
    expect(plan).toEqual({ file: '/usr/bin/node', args: ['--version', 'x'], options: {} });
  });

  it('is an identity plan on darwin too', () => {
    const plan = planSpawn(['npx', '-y', 'pkg'], {}, 'darwin');
    expect(plan).toEqual({ file: 'npx', args: ['-y', 'pkg'], options: {} });
  });

  it('spawns a resolved .exe directly on win32, no shell', () => {
    const env = { PATH: 'C:\\nodejs' };
    const fs = fakeFs(['C:\\nodejs\\node.exe']);
    const plan = planSpawn(['node', '--version'], env, 'win32', fs);
    expect(plan).toEqual({
      file: 'C:\\nodejs\\node.EXE',
      args: ['--version'],
      options: { windowsHide: true },
    });
  });

  it('routes a resolved .cmd shim through cmd.exe with windowsVerbatimArguments', () => {
    const env = { PATH: 'C:\\npm', ComSpec: 'C:\\Windows\\System32\\cmd.exe' };
    const fs = fakeFs(['C:\\npm\\npx.cmd']);
    const plan = planSpawn(['npx', '-y', '@modelcontextprotocol/server-foo'], env, 'win32', fs);

    expect(plan.file).toBe('C:\\Windows\\System32\\cmd.exe');
    expect(plan.options).toEqual({ windowsVerbatimArguments: true, windowsHide: true });
    expect(plan.args[0]).toBe('/d');
    expect(plan.args[1]).toBe('/s');
    expect(plan.args[2]).toBe('/c');
    expect(plan.args).toHaveLength(4);
    // The whole escaped command line is one token, wrapped in an outer pair
    // of plain (unescaped) quotes.
    const line = plan.args[3]!;
    expect(line.startsWith('"')).toBe(true);
    expect(line.endsWith('"')).toBe(true);
  });

  it('routes a .bat file (uppercase extension) through cmd.exe too', () => {
    const plan = planSpawn(['C:\\tools\\run.BAT', 'arg'], {}, 'win32');
    expect(plan.file).toBe('cmd.exe'); // no ComSpec in env -> default fallback
    expect(plan.options.windowsVerbatimArguments).toBe(true);
  });

  it('falls back to the default cmd.exe when ComSpec is not in env', () => {
    const plan = planSpawn(['C:\\tools\\run.cmd'], {}, 'win32');
    expect(plan.file).toBe('cmd.exe');
  });

  it('picks up ComSpec under any casing (Windows env var casing is unreliable)', () => {
    const plan = planSpawn(['C:\\tools\\run.cmd'], { COMSPEC: 'C:\\cmd.exe' }, 'win32');
    expect(plan.file).toBe('C:\\cmd.exe');
  });

  describe('escaping (cross-spawn algorithm) inside the built command line', () => {
    const lineFor = (argv: string[], env: NodeJS.ProcessEnv = {}): string =>
      planSpawn(argv, env, 'win32').args[3]!;
    /** The command line minus planSpawn's own outer pair of plain quotes. */
    const innerFor = (argv: string[]): string => lineFor(argv).slice(1, -1);

    // Every argument is escaped TWICE (see escapeCmdArg): once for the
    // cmd.exe that launches the .cmd/.bat file, once for the batch file's own
    // re-parse of %* / %1. So a wrapped token reads ^^^"...^^^" on the wire:
    // pass one turns ^^^" into ^", the batch file's pass turns ^" into ".

    it('quotes an argument containing a space (space is a cmd.exe metacharacter too)', () => {
      expect(innerFor(['C:\\tools\\run.cmd', 'hello world'])).toBe(
        'C:\\tools\\run.cmd ^^^"hello^^^ world^^^"',
      );
    });

    it('escapes an embedded double quote with a backslash', () => {
      expect(innerFor(['C:\\tools\\run.cmd', 'say "hi"'])).toBe(
        'C:\\tools\\run.cmd ^^^"say^^^ \\^^^"hi\\^^^"^^^"',
      );
    });

    it('doubles a trailing backslash so it does not escape the closing quote', () => {
      expect(innerFor(['C:\\tools\\run.cmd', 'C:\\path\\'])).toBe(
        'C:\\tools\\run.cmd ^^^"C:\\path\\\\^^^"',
      );
    });

    it('doubles backslashes that immediately precede a quote', () => {
      // a\"b -> the backslash run before the quote is doubled, then the quote escaped: a\\\"b
      expect(innerFor(['C:\\tools\\run.cmd', 'a\\"b'])).toBe(
        'C:\\tools\\run.cmd ^^^"a\\\\\\^^^"b^^^"',
      );
    });

    it('caret-escapes every cmd.exe metacharacter, twice: ( ) [ ] % ! ^ " ` < > & | ; , space * ?', () => {
      const line = innerFor(['C:\\tools\\run.cmd', 'a&b|c%d^e<f>g(h)i!j[k]l`m;n,o*p?q']);
      for (const ch of ['&', '|', '%', '<', '>', '(', ')', '!', '[', ']', '`', ';', ',', '*', '?']) {
        expect(line).toContain(`^^^${ch}`);
      }
      // a literal caret in the argument: escaped once (^^), then that pair escaped again (^^^^)
      expect(line).toContain('d^^^^e');
      expect(line).toBe(
        'C:\\tools\\run.cmd ^^^"a^^^&b^^^|c^^^%d^^^^e^^^<f^^^>g^^^(h^^^)i^^^!j^^^[k^^^]l^^^`m^^^;n^^^,o^^^*p^^^?q^^^"',
      );
    });

    it('an empty argument survives as an empty quoted token', () => {
      expect(innerFor(['C:\\tools\\run.cmd', '', 'x'])).toBe('C:\\tools\\run.cmd ^^^"^^^" ^^^"x^^^"');
    });

    it('does not quote the command; a space in its path is caret-escaped so it stays one token', () => {
      // `C:\Program Files\nodejs\npx.cmd` is the default global npm shim
      // location on Windows — the case this must get right.
      expect(innerFor(['C:\\Program Files\\nodejs\\npx.cmd', '-y', 'pkg'])).toBe(
        'C:\\Program^ Files\\nodejs\\npx.cmd ^^^"-y^^^" ^^^"pkg^^^"',
      );
    });

    it('normalizes the command path (forward slashes, dot segments) before escaping it', () => {
      expect(innerFor(['C:/tools/./run.cmd'])).toBe('C:\\tools\\run.cmd');
    });

    it('joins the resolved command and every escaped argument with spaces, in order', () => {
      const inner = innerFor(['C:\\tools\\run.cmd', 'first', 'second arg']);
      expect(inner).toBe('C:\\tools\\run.cmd ^^^"first^^^" ^^^"second^^^ arg^^^"');
    });
  });
});
