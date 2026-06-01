import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockDb, mockStmt } = vi.hoisted(() => {
  const mockStmt = {
    run: vi.fn(() => ({ lastInsertRowid: 1, changes: 1 })),
    get: vi.fn(() => undefined),
    all: vi.fn(() => []),
  };
  const mockDb = {
    prepare: vi.fn(() => mockStmt),
    exec: vi.fn(),
    pragma: vi.fn(),
    close: vi.fn(),
  };
  return { mockDb, mockStmt };
});

vi.mock('better-sqlite3', () => ({
  default: vi.fn(function () { return mockDb; }),
}));

import * as threatDb from './threat_db';

beforeEach(() => {
  mockStmt.run.mockClear();
  mockStmt.get.mockClear();
  mockStmt.all.mockClear();
  mockDb.prepare.mockClear();
  mockDb.exec.mockClear();
  mockDb.pragma.mockClear();
  mockDb.close.mockClear();
});

describe('addThreat', () => {
  it('inserts a threat record and returns an id', () => {
    const id = threatDb.addThreat({ type: 'pr', source: 'test-repo', severity: 'HIGH' });
    expect(id).toBe(1);
    expect(mockStmt.run).toHaveBeenCalled();
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO threats'));
  });

  it('inserts a threat with author and updates threat_authors', () => {
    mockStmt.get.mockReturnValue(undefined);
    const id = threatDb.addThreat({ type: 'pr', source: 'test-repo', author: 'bob', authorEmail: 'bob@test.com' });
    expect(id).toBe(1);
    expect(mockStmt.get).toHaveBeenCalledWith('bob');
    expect(mockStmt.run).toHaveBeenCalledTimes(2);
  });

  it('updates existing threat_author when author already exists', () => {
    mockStmt.get.mockReturnValue({ author: 'bob', threat_count: 5 });
    threatDb.addThreat({ type: 'pr', source: 'test-repo', author: 'bob' });
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE threat_authors'));
    expect(mockStmt.run).toHaveBeenCalledTimes(2);
  });

  it('handles null fields gracefully', () => {
    threatDb.addThreat({ type: 'pr', source: 'test' });
    expect(mockStmt.run).toHaveBeenCalledWith('pr', 'test', null, null, null, 'HIGH', null, null, null, null);
  });
});

describe('getThreatsByAuthor', () => {
  it('returns threats for a given author', () => {
    const expected = [{ id: 1, type: 'pr', source: 'test', author: 'alice' }];
    mockStmt.all.mockReturnValue(expected);
    const result = threatDb.getThreatsByAuthor('alice');
    expect(result).toEqual(expected);
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('WHERE author ='));
  });

  it('returns empty array for unknown author', () => {
    mockStmt.all.mockReturnValue([]);
    const result = threatDb.getThreatsByAuthor('unknown');
    expect(result).toEqual([]);
  });
});

describe('getRecentThreats', () => {
  it('returns recent threats with default limit', () => {
    const expected = [{ id: 1 }, { id: 2 }];
    mockStmt.all.mockReturnValue(expected);
    const result = threatDb.getRecentThreats();
    expect(result).toEqual(expected);
    expect(mockStmt.all).toHaveBeenCalledWith(20);
  });

  it('returns recent threats with custom limit', () => {
    mockStmt.all.mockReturnValue([]);
    threatDb.getRecentThreats(5);
    expect(mockStmt.all).toHaveBeenCalledWith(5);
  });
});

describe('getHighRiskAuthors', () => {
  it('returns authors with HIGH or CRITICAL risk', () => {
    const expected = [
      { author: 'alice', risk_level: 'CRITICAL', threat_count: 10 },
      { author: 'bob', risk_level: 'HIGH', threat_count: 5 },
    ];
    mockStmt.all.mockReturnValue(expected);
    const result = threatDb.getHighRiskAuthors();
    expect(result).toEqual(expected);
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('risk_level'));
  });

  it('returns empty array when no high risk authors', () => {
    mockStmt.all.mockReturnValue([]);
    const result = threatDb.getHighRiskAuthors();
    expect(result).toEqual([]);
  });
});

describe('getThreatAuthor', () => {
  it('returns threat author by name', () => {
    const expected = { author: 'alice', risk_level: 'HIGH', threat_count: 3 };
    mockStmt.get.mockReturnValue(expected);
    const result = threatDb.getThreatAuthor('alice');
    expect(result).toEqual(expected);
  });

  it('returns undefined for unknown author', () => {
    mockStmt.get.mockReturnValue(undefined);
    const result = threatDb.getThreatAuthor('unknown');
    expect(result).toBeUndefined();
  });
});

describe('setAuthorRiskLevel', () => {
  it('updates the risk level for an author', () => {
    threatDb.setAuthorRiskLevel('alice', 'CRITICAL');
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE threat_authors'));
    expect(mockStmt.run).toHaveBeenCalledWith('CRITICAL', 'alice');
  });
});

describe('addThreatPattern', () => {
  it('inserts a new threat pattern', () => {
    mockStmt.get.mockReturnValue(undefined);
    threatDb.addThreatPattern('eval', 'Dynamic code execution', 'HIGH');
    expect(mockStmt.run).toHaveBeenCalledWith('eval', 'Dynamic code execution', 'HIGH');
  });

  it('increments occurrence for existing pattern', () => {
    mockStmt.get.mockReturnValue({ pattern: 'eval', occurrence_count: 1 });
    threatDb.addThreatPattern('eval', 'Dynamic code execution', 'HIGH');
    expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE threat_patterns'));
  });
});

describe('getThreatPatterns', () => {
  it('returns all patterns ordered by occurrence', () => {
    const expected = [{ pattern: 'eval', occurrence_count: 5 }];
    mockStmt.all.mockReturnValue(expected);
    const result = threatDb.getThreatPatterns();
    expect(result).toEqual(expected);
  });

  it('filters patterns by severity', () => {
    const expected = [{ pattern: 'eval', severity: 'HIGH', occurrence_count: 5 }];
    mockStmt.all.mockReturnValue(expected);
    const result = threatDb.getThreatPatterns('HIGH');
    expect(mockStmt.all).toHaveBeenCalledWith('HIGH');
    expect(result).toEqual(expected);
  });
});

describe('correlateFindings', () => {
  it('returns default result when no author, pattern, or diffHash given', () => {
    const result = threatDb.correlateFindings();
    expect(result).toEqual({
      threatCount: 0,
      knownAuthor: false,
      authorThreats: [],
      authorRiskLevel: 'unknown',
      patternMatches: [],
    });
  });

  it('identifies known author and returns their threats', () => {
    mockStmt.get.mockReturnValue({ author: 'alice', risk_level: 'HIGH', threat_count: 3, patterns: '[]', repos: '[]' });
    mockStmt.all.mockReturnValue([{ id: 1, type: 'pr', author: 'alice' }]);

    const result = threatDb.correlateFindings('alice');
    expect(result.knownAuthor).toBe(true);
    expect(result.authorRiskLevel).toBe('HIGH');
    expect(result.authorThreats).toHaveLength(1);
    expect(result.threatCount).toBe(3);
  });

  it('matches patterns in findings', () => {
    const patterns = [
      { pattern: 'eval', description: 'Code execution', severity: 'HIGH' },
    ];
    mockStmt.all.mockReturnValue(patterns);

    const result = threatDb.correlateFindings('', 'this contains eval in the code');
    expect(result.patternMatches).toHaveLength(1);
    expect(result.patternMatches[0].pattern).toBe('eval');
  });

  it('matches patterns case-insensitively', () => {
    const patterns = [{ pattern: 'EVAL', description: 'Code exec' }];
    mockStmt.all.mockReturnValue(patterns);

    const result = threatDb.correlateFindings('', 'uses eval function');
    expect(result.patternMatches).toHaveLength(1);
  });

  it('counts diff hash signature matches', () => {
    mockStmt.get.mockReturnValue(undefined);
    mockStmt.all.mockReturnValue([{ id: 1, signature: 'hash123' }]);

    const result = threatDb.correlateFindings('', '', 'hash123');
    expect(result.threatCount).toBe(1);
  });

  it('aggregates threat count from author and signature', () => {
    mockStmt.get.mockReturnValue({ author: 'bob', risk_level: 'CRITICAL', threat_count: 2, patterns: '[]', repos: '[]' });
    mockStmt.all
      .mockReturnValueOnce([{ id: 1, author: 'bob' }])       // getThreatsByAuthor
      .mockReturnValueOnce([{ id: 2, signature: 'abc' }])     // getThreatsBySignature
      .mockReturnValueOnce([]);                                // getThreatPatterns

    const result = threatDb.correlateFindings('bob', 'test finding', 'abc');
    expect(result.threatCount).toBe(3);
    expect(result.knownAuthor).toBe(true);
    expect(result.patternMatches).toHaveLength(0);
  });
});

describe('closeDb', () => {
  it('closes the database connection', () => {
    threatDb.closeDb();
    expect(mockDb.close).toHaveBeenCalled();
  });
});
