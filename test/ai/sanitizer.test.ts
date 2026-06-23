import { describe, it, expect } from 'vitest'
import { sanitizeAIOutput, sanitizeJSONOutput, sanitizeSummary, sanitizeBulletPoint } from '../../src/ai/sanitizer'

describe('sanitizeAIOutput', () => {
  it('removes bold markdown', () => {
    expect(sanitizeAIOutput('This is **bold** text')).toBe('This is bold text')
    expect(sanitizeAIOutput('Also __bold__ here')).toBe('Also bold here')
  })

  it('removes italic markdown', () => {
    expect(sanitizeAIOutput('This is *italic* text')).toBe('This is italic text')
    expect(sanitizeAIOutput('Also _italic_ here')).toBe('Also italic here')
  })

  it('removes both bold+italic', () => {
    expect(sanitizeAIOutput('***bold italic***')).toBe('bold italic')
    expect(sanitizeAIOutput('___bold italic___')).toBe('bold italic')
  })

  it('removes inline code', () => {
    expect(sanitizeAIOutput('Use the `foo()` function')).toBe('Use the foo() function')
  })

  it('removes code blocks with language', () => {
    const input = 'Here is code:\n```javascript\nconst x = 1\n```\nEnd'
    const expected = 'Here is code:\nconst x = 1\nEnd'
    expect(sanitizeAIOutput(input)).toBe(expected)
  })

  it('removes code blocks without language', () => {
    const input = '```\nplain code\n```'
    expect(sanitizeAIOutput(input)).toBe('plain code')
  })

  it('removes fenced code with ~~~', () => {
    const input = '~~~\ncode block\n~~~'
    expect(sanitizeAIOutput(input)).toBe('code block')
  })

  it('removes HTML tags', () => {
    expect(sanitizeAIOutput('Text <b>with</b> tags')).toBe('Text with tags')
    expect(sanitizeAIOutput('<div>block</div>')).toBe('block')
  })

  it('removes markdown headers', () => {
    expect(sanitizeAIOutput('# Title')).toBe('Title')
    expect(sanitizeAIOutput('## Subtitle')).toBe('Subtitle')
    expect(sanitizeAIOutput('### H3')).toBe('H3')
  })

  it('removes markdown links but keeps text', () => {
    expect(sanitizeAIOutput('See [docs](https://example.com)')).toBe('See docs')
  })

  it('removes images but keeps alt text', () => {
    expect(sanitizeAIOutput('![screenshot](image.png)')).toBe('screenshot')
  })

  it('removes blockquotes', () => {
    expect(sanitizeAIOutput('> quoted text')).toBe('quoted text')
  })

  it('removes horizontal rules', () => {
    expect(sanitizeAIOutput('before\n---\nafter')).toBe('before\nafter')
  })

  it('removes strikethrough', () => {
    expect(sanitizeAIOutput('~~striked~~')).toBe('striked')
  })

  it('collapses multiple newlines', () => {
    const input = 'line1\n\n\n\nline2'
    expect(sanitizeAIOutput(input)).toBe('line1\n\nline2')
  })

  it('trims whitespace', () => {
    expect(sanitizeAIOutput('  hello  ')).toBe('hello')
  })

  it('returns empty string for nullish input', () => {
    expect(sanitizeAIOutput('')).toBe('')
    expect(sanitizeAIOutput(null as unknown as string)).toBe('')
    expect(sanitizeAIOutput(undefined as unknown as string)).toBe('')
  })

  it('handles complex mixed markdown', () => {
    const input = `
# Summary

This PR **adds** a new feature:
- Item *one*
- Item \`two\`

> Note: see [link](url)

\`\`\`ts
const x = 1
\`\`\`
    `
    const result = sanitizeAIOutput(input)
    expect(result).not.toContain('#')
    expect(result).not.toContain('**')
    expect(result).not.toContain('`')
    expect(result).not.toContain('>')
    expect(result).not.toContain('[')
    expect(result).toContain('Summary')
    expect(result).toContain('adds')
    expect(result).toContain('Item')
    expect(result).toContain('const x = 1')
  })
})

describe('sanitizeJSONOutput', () => {
  it('extracts JSON from code block', () => {
    const raw = '```json\n{"key": "value"}\n```'
    expect(sanitizeJSONOutput(raw)).toBe('{"key": "value"}')
  })

  it('extracts JSON from triple-backtick without lang', () => {
    const raw = '```\n{"a": 1}\n```'
    expect(sanitizeJSONOutput(raw)).toBe('{"a": 1}')
  })

  it('returns raw text if no JSON found', () => {
    const raw = 'just some text'
    expect(sanitizeJSONOutput(raw)).toBe(raw)
  })

  it('extracts JSON from surrounding text', () => {
    const raw = 'Here is the result: {"key": "value"} rest'
    expect(sanitizeJSONOutput(raw)).toBe('{"key": "value"}')
  })

  it('handles arrays', () => {
    const raw = 'Some text\n[1, 2, 3]\nmore'
    expect(sanitizeJSONOutput(raw)).toBe('[1, 2, 3]')
  })
})

describe('sanitizeSummary', () => {
  it('collapses to single line', () => {
    const input = 'This is\n\na **summary**\n\nwith *formatting*'
    const result = sanitizeSummary(input)
    expect(result).toBe('This is a summary with formatting')
    expect(result).not.toContain('\n')
  })
})

describe('sanitizeBulletPoint', () => {
  it('removes leading dash', () => {
    expect(sanitizeBulletPoint('- item')).toBe('item')
  })

  it('removes leading asterisk', () => {
    expect(sanitizeBulletPoint('* item')).toBe('item')
  })

  it('removes leading plus', () => {
    expect(sanitizeBulletPoint('+ item')).toBe('item')
  })
})
