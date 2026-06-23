import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { execSync } from 'child_process'
import type { AIBackendStatus, DetectedModel } from './types'

const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models')

export function detectAllModels(): DetectedModel[] {
  const models: DetectedModel[] = []

  if (checkOllama()) {
    try {
      const out = execSync('ollama list', { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
      const lines = out.trim().split('\n').slice(1)
      for (const line of lines) {
        const name = line.split(/\s+/)[0]
        if (name) {
          models.push({ id: `ollama:${name}`, name, backend: 'ollama', modelPath: name })
        }
      }
    } catch {}
  }

  const ggufFiles = findGgufFiles()
  for (const filePath of ggufFiles) {
    const name = path.basename(filePath)
    models.push({ id: `gguf:${name}`, name, backend: 'node-llama-cpp', modelPath: filePath })
  }

  return models
}

export function detectAIBackend(selectedModel?: string): AIBackendStatus {
  const allModels = detectAllModels()
  const ggufFiles = findGgufFiles()

  if (selectedModel) {
    const match = allModels.find(m => m.id === selectedModel)
    if (match) {
      return { available: true, backend: match.backend, modelName: match.name, modelPath: match.modelPath, availableModels: allModels }
    }
  }

  const ollamaAvailable = checkOllama()

  if (ollamaAvailable) {
    const ollamaModels = allModels.filter(m => m.backend === 'ollama')
    if (ollamaModels.length > 0) {
      const m = ollamaModels[0]
      return { available: true, backend: 'ollama', modelName: m.name, modelPath: m.modelPath, availableModels: allModels }
    }
  }

  if (ggufFiles.length > 0) {
    const preferred = ggufFiles.find(f => f.includes('1.5b') || f.includes('1.5B'))
    const modelPath = preferred || ggufFiles[0]
    const modelName = path.basename(modelPath)
    return { available: true, backend: 'node-llama-cpp', modelName, modelPath, availableModels: allModels }
  }

  return {
    available: false,
    backend: 'none',
    modelName: '',
    modelPath: '',
    error: buildSetupInstructions(ollamaAvailable),
    availableModels: allModels,
  }
}

export async function checkModelHealth(modelName?: string): Promise<{ available: boolean; modelName: string; backend: string; error?: string }> {
  if (!modelName) {
    const status = detectAIBackend()
    return { available: status.available, modelName: status.modelName, backend: status.backend, error: status.error }
  }

  if (modelName.startsWith('ollama:')) {
    const name = modelName.replace(/^ollama:/, '')
    try {
      const { execSync } = require('child_process')
      execSync(`ollama show ${name}`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] })
      return { available: true, modelName: name, backend: 'ollama' }
    } catch {
      return { available: false, modelName: name, backend: 'ollama', error: `Ollama model "${name}" not found` }
    }
  }

  if (modelName.startsWith('gguf:')) {
    const filePath = modelName.replace(/^gguf:/, '')
    try {
      const fs = require('fs')
      if (fs.existsSync(filePath)) {
        return { available: true, modelName: filePath, backend: 'node-llama-cpp' }
      }
      return { available: false, modelName: filePath, backend: 'node-llama-cpp', error: `GGUF file not found: ${filePath}` }
    } catch {
      return { available: false, modelName: filePath, backend: 'node-llama-cpp', error: 'Cannot access GGUF file' }
    }
  }

  return { available: false, modelName: '', backend: 'none', error: `Unknown model: ${modelName}` }
}

export function buildSetupInstructions(hasOllama: boolean): string {
  if (hasOllama) {
    return `Ollama detectado pero sin modelo. Corre: ollama pull qwen2.5:1.5b`
  }
  return `No se detectó backend AI.

Opción 1 — Descarga un modelo .gguf en:
  ${MODELS_DIR}
  Recomendado: Qwen 2.5 1.5B Instruct (Q4_K_M)

Opción 2 — Instala Ollama desde https://ollama.com y corre:
  ollama pull qwen2.5:1.5b`
}

function checkOllama(): boolean {
  try {
    execSync('ollama --version', { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] })
    return true
  } catch {
    return false
  }
}

function findGgufFiles(): string[] {
  try {
    if (!fs.existsSync(MODELS_DIR)) return []
    return fs.readdirSync(MODELS_DIR)
      .filter(f => f.endsWith('.gguf'))
      .map(f => path.join(MODELS_DIR, f))
  } catch {
    return []
  }
}
