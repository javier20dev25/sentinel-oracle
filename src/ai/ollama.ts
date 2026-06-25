import { sanitizeJSONOutput, sanitizeSummary, sanitizeBulletPoint } from './sanitizer'

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434'

interface OllamaGenerateResponse {
  model: string
  created_at: string
  response: string
  done: boolean
  context?: number[]
  total_duration?: number
  load_duration?: number
  prompt_eval_count?: number
  prompt_eval_duration?: number
  eval_count?: number
  eval_duration?: number
}

export async function ollamaGenerate(model: string, prompt: string, systemPrompt?: string): Promise<string> {
  const body: Record<string, unknown> = { model, prompt, stream: false }
  if (systemPrompt) body.system = systemPrompt

  const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(300000),
  })

  if (!res.ok) {
    const errBody = await res.text().catch(() => '')
    throw new Error(`Ollama API error ${res.status}: ${errBody.slice(0, 200)}`)
  }

  const data = (await res.json()) as OllamaGenerateResponse
  return data.response || ''
}

export async function ollamaChat(model: string, messages: { role: string; content: string }[]): Promise<string> {
  const res = await fetch(`${OLLAMA_HOST}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, stream: false }),
    signal: AbortSignal.timeout(300000),
  })

  if (!res.ok) {
    const errBody = await res.text().catch(() => '')
    throw new Error(`Ollama chat error ${res.status}: ${errBody.slice(0, 200)}`)
  }

  const data = (await res.json()) as { message: { role: string; content: string } }
  return data.message?.content || ''
}

export async function ollamaGenerateJSON<T>(model: string, prompt: string, systemPrompt?: string): Promise<T | null> {
  try {
    const raw = await ollamaGenerate(model, prompt, systemPrompt)
    const cleaned = sanitizeJSONOutput(raw)

    if (cleaned !== raw) {
      const parsed = JSON.parse(cleaned)
      return parsed as T
    }

    try {
      return JSON.parse(cleaned) as T
    } catch {
      const jsonStart = cleaned.indexOf('{')
      const jsonEnd = cleaned.lastIndexOf('}')
      if (jsonStart !== -1 && jsonEnd !== -1) {
        const extracted = cleaned.slice(jsonStart, jsonEnd + 1)
        return JSON.parse(extracted) as T
      }
      return null
    }
  } catch (err) {
    console.warn(`[ollama] generateJSON failed: ${err instanceof Error ? err.message : err}`)
    return null
  }
}

export async function ollamaListModels(): Promise<string[]> {
  try {
    const res = await fetch(`${OLLAMA_HOST}/api/tags`, {
      signal: AbortSignal.timeout(5000),
    })
    if (!res.ok) return []
    const data = (await res.json()) as { models: { name: string }[] }
    return (data.models || []).map(m => m.name)
  } catch {
    return []
  }
}
