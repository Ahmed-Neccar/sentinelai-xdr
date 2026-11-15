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
