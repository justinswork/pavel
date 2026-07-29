import { describe, it, expect } from 'vitest';
import { agePredicate } from '../src/request';

describe('agePredicate', () => {
  it('maps a minimum age to its ISO element identifier', () => {
    expect(agePredicate(21)).toBe('age_over_21');
    expect(agePredicate(18)).toBe('age_over_18');
  });
});
