/** Primary website portfolio categories (display order). */
const WEBSITE_PROJECT_CATEGORIES = [
  'Hospitality',
  'Residential',
  'Commercial',
  'Interior',
  'Apartments'
];

/** Kept for existing records; not offered for new projects. */
const LEGACY_WEBSITE_PROJECT_CATEGORIES = ['Urban', 'Conceptual'];

function isValidWebsiteProjectCategory(category) {
  const cat = (category || '').trim();
  if (!cat) return false;
  return WEBSITE_PROJECT_CATEGORIES.includes(cat) ||
    LEGACY_WEBSITE_PROJECT_CATEGORIES.includes(cat);
}

function categoryToFilterSlug(category) {
  return String(category || '').trim().toLowerCase();
}

module.exports = {
  WEBSITE_PROJECT_CATEGORIES,
  LEGACY_WEBSITE_PROJECT_CATEGORIES,
  isValidWebsiteProjectCategory,
  categoryToFilterSlug
};
