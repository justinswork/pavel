/**
 * Minimal store catalog. Some items are age-restricted (21+).
 * Restricted items are listed last so on phones they sit just above the cart.
 */

export interface Product {
  id: string;
  name: string;
  blurb: string;
  price: number; // USD
  emoji: string;
  ageRestricted: boolean;
}

export const MIN_AGE = 21;

export const CATALOG: Product[] = [
  {
    id: 'coffee',
    name: 'Single-Origin Coffee Beans',
    blurb: 'Ethiopia Yirgacheffe, whole bean. 12oz.',
    price: 16.0,
    emoji: '☕',
    ageRestricted: false,
  },
  {
    id: 'sparkling',
    name: 'Sparkling Water — 12 Pack',
    blurb: 'Lightly carbonated, zero sugar.',
    price: 6.5,
    emoji: '💧',
    ageRestricted: false,
  },
  {
    id: 'chocolate',
    name: '85% Dark Chocolate Bar',
    blurb: 'Single-estate cacao. 100g.',
    price: 4.25,
    emoji: '🍫',
    ageRestricted: false,
  },
  {
    id: 'chef-knife',
    name: "Chef's Kitchen Knife",
    blurb: '8" high-carbon steel. Age-restricted blade.',
    price: 49.0,
    emoji: '🔪',
    ageRestricted: true,
  },
  {
    id: 'ipa-6pack',
    name: 'Hazy IPA — 6 Pack',
    blurb: 'Citrus-forward craft ale. 6 × 12oz.',
    price: 13.5,
    emoji: '🍺',
    ageRestricted: true,
  },
  {
    id: 'cab-sauv',
    name: 'Reserve Cabernet Sauvignon',
    blurb: 'Full-bodied red, oak-aged. 750ml.',
    price: 24.0,
    emoji: '🍷',
    ageRestricted: true,
  },
];

export const CATALOG_BY_ID = new Map(CATALOG.map((p) => [p.id, p]));
