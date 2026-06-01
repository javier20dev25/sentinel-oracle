/**
 * Tone/Mood system for AI responses.
 * Includes a terminal modal selector (arrow keys + Enter).
 */

import * as pc from 'picocolors';

export interface Tone {
  id: string;
  label: string;
  description: string;
  systemInstruction: string;
}

export const TONES: Tone[] = [
  {
    id: 'neutral',
    label: 'Neutral',
    description: 'Balanced, professional — default tone',
    systemInstruction: 'Respond in a balanced, professional tone. Be clear and direct without excessive formality or casualness.',
  },
  {
    id: 'divertido',
    label: 'Divertido',
    description: 'Light, witty, and fun — but never at the cost of accuracy',
    systemInstruction: 'Use a light, witty tone with occasional humor. Keep it fun but never sacrifice accuracy or clarity. Security findings are serious but the delivery can be engaging.',
  },
  {
    id: 'serio',
    label: 'Serio',
    description: 'Formal, direct, no-nonsense',
    systemInstruction: 'Respond in a formal, direct tone. Be concise and authoritative. No humor, no embellishments — just facts and actionable recommendations.',
  },
  {
    id: 'detallado',
    label: 'Detallado',
    description: 'Thorough technical deep-dive with full context',
    systemInstruction: 'Provide extremely detailed technical analysis. Include code snippets, CVE references, MITRE ATT&CK mappings, exploit scenarios, and step-by-step remediation. Assume the user is a security engineer.',
  },
  {
    id: 'conciso',
    label: 'Conciso',
    description: 'Short, direct answers — minimal fluff',
    systemInstruction: 'Keep responses as short as possible. State findings in 1-2 sentences each. No explanations unless asked. Prioritize speed of information delivery.',
  },
  {
    id: 'didactico',
    label: 'Didactico',
    description: 'Educational — explains concepts and teaches security',
    systemInstruction: 'Adopt a teaching tone. Explain security concepts, why certain patterns are dangerous, and how to think about threats. Use analogies and examples. The goal is to educate while analyzing.',
  },
  {
    id: 'urgente',
    label: 'Urgente',
    description: 'Urgent — prioritizes critical findings, uses alert language',
    systemInstruction: 'Adopt an urgent, alert tone. Highlight critical and high-severity findings first and prominently. Use strong language for dangerous patterns. Downplay low-severity items. Push for immediate action on critical threats.',
  },
];

let currentToneIndex = 0;

export function getCurrentTone(): Tone {
  return TONES[currentToneIndex];
}

export function setTone(id: string): boolean {
  const idx = TONES.findIndex(t => t.id === id);
  if (idx === -1) return false;
  currentToneIndex = idx;
  return true;
}

export function getToneSystemPrompt(): string {
  return getCurrentTone().systemInstruction;
}

// ─── Terminal Modal Selector ──────────────────────────────────

/**
 * Renders an interactive selector in the terminal.
 * Arrow keys to move, Enter to select, Esc to cancel.
 * Returns the selected tone id, or null if cancelled.
 */
export async function selectToneModal(): Promise<string | null> {
  let selected = currentToneIndex;

  const render = () => {
    const lines: string[] = [];
    lines.push('');
    lines.push(pc.cyan('  Select response tone (arrows + enter, esc to cancel):'));
    lines.push('');
    TONES.forEach((t, i) => {
      const pointer = i === selected ? pc.cyan(' \u25B6') : '  ';
      const label = i === selected ? pc.bold(pc.cyan(t.label)) : pc.gray(t.label);
      const desc = i === selected ? pc.white(t.description) : pc.gray(t.description);
      lines.push(`  ${pointer} ${label}`);
      lines.push(`      ${desc}`);
      lines.push('');
    });
    lines.push(pc.gray('  \u2191/\u2193 navigate  |  Enter select  |  Esc cancel'));
    return lines.join('\n');
  };

  // Enter raw mode
  const wasRaw = process.stdin.isRaw;
  const wasPaused = process.stdin.isPaused();
  let rawEntered = false;
  try {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    rawEntered = true;
  } catch {
    return TONES[currentToneIndex].id; // fallback
  }

  return new Promise(resolve => {
    const cleanup = () => {
      try { process.stdin.setRawMode(wasRaw || false); } catch {}
      if (!wasPaused) try { process.stdin.pause(); } catch {}
      process.stdin.removeAllListeners('data');
    };

    process.stdout.write(render());

    const onData = (data: Buffer) => {
      const b = data[0];

      // Arrow keys send escape sequences: \x1b[A (up), \x1b[B (down)
      if (b === 0x1b && data.length >= 3) {
        if (data[1] === 0x5b) {
          if (data[2] === 0x41) {
            // Up arrow
            selected = Math.max(0, selected - 1);
            // Move cursor up by 3 lines per option (roughly)
            const totalLines = TONES.length * 3 + 3;
            process.stdout.write(`\x1b[${totalLines}A`); // move up
            process.stdout.write('\x1b[J'); // clear to end
            process.stdout.write(render());
          } else if (data[2] === 0x42) {
            // Down arrow
            selected = Math.min(TONES.length - 1, selected + 1);
            const totalLines = TONES.length * 3 + 3;
            process.stdout.write(`\x1b[${totalLines}A`);
            process.stdout.write('\x1b[J');
            process.stdout.write(render());
          }
        }
        return;
      }

      // Enter
      if (b === 0x0d || b === 0x0a) {
        cleanup();
        currentToneIndex = selected;
        // Clear the modal from screen
        const totalLines = TONES.length * 3 + 4;
        process.stdout.write(`\x1b[${totalLines}A`);
        process.stdout.write('\x1b[J');
        console.log(`  ${pc.green('Tone set:')} ${pc.bold(TONES[selected].label)} — ${TONES[selected].description}`);
        resolve(TONES[selected].id);
        return;
      }

      // Esc
      if (b === 0x1b && data.length === 1) {
        cleanup();
        const totalLines = TONES.length * 3 + 4;
        process.stdout.write(`\x1b[${totalLines}A`);
        process.stdout.write('\x1b[J');
        resolve(null);
        return;
      }
    };

    process.stdin.on('data', onData);
  });
}
