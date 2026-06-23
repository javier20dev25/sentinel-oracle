export function sanitizeAIOutput(text: string): string {
  if (!text) return ''

  let result = text

  result = result.replace(/```[\s\S]*?```/g, match => {
    const inner = match.replace(/```/g, '').replace(/^[a-z]*\n/, '')
    return inner.trim()
  })

  result = result.replace(/~~~[\s\S]*?~~~/g, match => {
    const inner = match.replace(/~~~/g, '').replace(/^[a-z]*\n/, '')
    return inner.trim()
  })

  result = result.replace(/`([^`]+)`/g, '$1')

  result = result.replace(/!\[([^\]]*)\]\([^)]+\)/g, '$1')

  result = result.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')

  result = result.replace(/^#{1,6}\s+/gm, '')

  result = result.replace(/(\*\*\*|___)(.*?)\1/g, '$2')
  result = result.replace(/(\*\*|__)(.*?)\1/g, '$2')
  result = result.replace(/(\*|_)(.*?)\1/g, '$2')
  result = result.replace(/(~~)(.*?)\1/g, '$2')

  result = result.replace(/^>\s+/gm, '')

  result = result.replace(/^[\s]*[-*+]\s+/gm, '')
  result = result.replace(/^[\s]*\d+[.)]\s+/gm, '')

  result = result.replace(/\n[-*_]{3,}\s*$/gm, '')
  result = result.replace(/^[-*_]{3,}\s*\n/gm, '')

  result = result.replace(/<[^>]*>/g, '')

  result = result.replace(/\n{3,}/g, '\n\n')

  return result.trim()
}

export function sanitizeJSONOutput(raw: string): string {
  let cleaned = raw.trim()

  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '')

  const braceStart = cleaned.indexOf('{')
  const braceEnd = cleaned.lastIndexOf('}')
  if (braceStart !== -1 && braceEnd !== -1 && braceEnd > braceStart) {
    cleaned = cleaned.slice(braceStart, braceEnd + 1)
  }

  try {
    JSON.parse(cleaned)
    return cleaned
  } catch {
    const bracketStart = cleaned.indexOf('[')
    const bracketEnd = cleaned.lastIndexOf(']')
    if (bracketStart !== -1 && bracketEnd !== -1 && bracketEnd > bracketStart) {
      cleaned = cleaned.slice(bracketStart, bracketEnd + 1)
    }
    try {
      JSON.parse(cleaned)
      return cleaned
    } catch {}
    return raw.trim()
  }
}

export function sanitizeSummary(text: string): string {
  return sanitizeAIOutput(text).replace(/\n+/g, ' ').replace(/\s{2,}/g, ' ').trim()
}

export function sanitizeBulletPoint(text: string): string {
  return sanitizeAIOutput(text).replace(/^[-*+]\s*/g, '').trim()
}
