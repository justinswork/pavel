/** Age-predicate helpers for building an Authorization Request. */

/** Assert a minAge is a usable integer predicate index; throws otherwise. */
export function assertValidMinAge(minAge: number): void {
  if (!Number.isInteger(minAge) || minAge < 1 || minAge > 120) {
    throw new RangeError(`minAge must be an integer in 1..120, got ${minAge}`);
  }
}

/** Map a minimum age to its ISO 18013-5 boolean element identifier. */
export function agePredicate(minAge: number): string {
  assertValidMinAge(minAge);
  return `age_over_${minAge}`;
}
