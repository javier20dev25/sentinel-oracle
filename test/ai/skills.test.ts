import { describe, it, expect } from 'vitest'
import { createSkills } from '../../src/ai/skills'

describe('createSkills', () => {
  it('returns a Map with all 5 skills', () => {
    const skills = createSkills({} as any, {} as any)
    expect(skills).toBeInstanceOf(Map)
    expect(skills.size).toBe(5)
    expect(skills.has('get_scan_result')).toBe(true)
    expect(skills.has('get_pr_files')).toBe(true)
    expect(skills.has('get_pr_history')).toBe(true)
    expect(skills.has('get_security_dna')).toBe(true)
    expect(skills.has('get_repository_stats')).toBe(true)
  })

  it('each skill has name and description', () => {
    const skills = createSkills({} as any, {} as any)
    for (const [name, skill] of skills) {
      expect(name).toBeTruthy()
      expect(skill.name).toBeTruthy()
      expect(skill.description).toBeTruthy()
    }
  })

  it('get_scan_result returns an error when no scan found', async () => {
    const mockDb = { getLatestScanResult: () => undefined } as any
    const skills = createSkills(mockDb, {} as any)
    const scanSkill = skills.get('get_scan_result')!
    const result = await scanSkill.execute(1)
    expect(result).toHaveProperty('error')
  })
})
