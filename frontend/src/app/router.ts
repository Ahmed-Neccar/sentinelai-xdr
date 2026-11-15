/**
 * A tiny hash router: the section the person is on lives in the address (`#/detections`), so a
 * link can be shared, reload keeps the place and the browser's back button works. There is no
 * router library because the app has one level of pages.
 */
const SECTIONS = ['Overview', 'Detections', 'Cases', 'Events', 'Hosts', 'Network discovery', 'Sensors', 'Ingestion', 'Cloud connectors', 'Notifications', 'Users', 'Rules', 'Audit', 'Settings'] as const
export type SectionName = (typeof SECTIONS)[number]

export const slugOf = (section: string): string => section.toLowerCase().replace(/\s+/g, '-')

export const hashForSection = (section: string): string => `#/${slugOf(section)}`

/** The section named by a hash such as `#/cases`, or null when the hash names none. */
export function sectionFromHash(hash: string): SectionName | null {
  const slug = hash.replace(/^#\/?/, '').split(/[/?]/)[0]
  return SECTIONS.find(section => slugOf(section) === slug) ?? null
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** The finding id in a hash such as `#/detections/<uuid>`, or null. */
export function detectionIdFromHash(hash: string): string | null {
  const parts = hash.replace(/^#\/?/, '').split(/[?]/)[0].split('/')
  return parts[0] === 'detections' && parts[1] && UUID_PATTERN.test(parts[1]) ? parts[1] : null
}

export const hashForDetection = (id: string): string => `#/detections/${id}`
