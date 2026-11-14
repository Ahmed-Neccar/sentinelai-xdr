import { translate, type Language } from './i18n'

// Fallback for text that reaches the screen without passing through t(): server-provided names
// (rule titles and descriptions), strings built in code, and anything a screen forgot to wrap.
// After React renders, every text node and every placeholder, title and aria-label whose whole
// text is a known English string is replaced by its Turkish text. Originals are remembered so
// switching back to English restores them. Text React rewrites later is translated again.

const ATTRIBUTES = ['placeholder', 'title', 'aria-label']
const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'CODE', 'PRE'])
// Text that starts with a known prefix keeps the rest as it is ("Investigation: <rule title>").
const PREFIXES: [string, string][] = [
  ['Investigation: ', 'İnceleme: '],
]

type Shown = { english: string; shown: string }

// Sentences the detectors build with numbers and addresses in them. Each pattern captures the
// variable parts and the replacement puts them into the Turkish sentence.
const SENTENCES: [RegExp, string][] = [
  [
    /^(\d+) distinct destination ports from (\S+) in (\d+)s starting (\S+) \(threshold (\d+)\)\.$/,
    '$2 adresinden $3 sn içinde $1 farklı hedef port, başlangıç $4 (eşik $5).',
  ],
  [
    /^(\d+) failures and (\d+) success\(es\) from (\S+) in window starting (\S+)\.$/,
    '$3 adresinden $4 başlangıçlı pencerede $1 hata ve $2 başarı.',
  ],
  [
    /^(\d+) matching events for (\S+) in a (\d+)s window starting (\S+) \(threshold (\d+)\)\. Synthetic or lab telemetry only unless labeled otherwise\.$/,
    '$2 için $3 sn\'lik pencerede $1 eşleşen olay, başlangıç $4 (eşik $5). Aksi belirtilmedikçe yalnızca sentetik veya laboratuvar telemetrisidir.',
  ],
  [
    /^(\d+) matching events for (\S+) in a (\d+)s window starting (\S+) \(threshold (\d+)\)\.$/,
    '$2 için $3 sn\'lik pencerede $1 eşleşen olay, başlangıç $4 (eşik $5).',
  ],
  [
    /^(\d+) distinct (\S+) values from (\S+) in (\d+)s starting (\S+) \(threshold (\d+)\)\.$/,
    '$3 adresinden $4 sn içinde $1 farklı $2 değeri, başlangıç $5 (eşik $6).',
  ],
]

export function translateString(value: string, language: Language): string {
  const trimmed = value.trim()
  if (!trimmed) return value
  let result = translate(trimmed, language)
  if (result === trimmed) {
    for (const [english, turkish] of PREFIXES) {
      if (trimmed.startsWith(english)) {
        result = turkish + translate(trimmed.slice(english.length), language)
        break
      }
    }
  }
  if (result === trimmed) {
    for (const [pattern, replacement] of SENTENCES) {
      if (pattern.test(trimmed)) {
        result = trimmed.replace(pattern, replacement)
        break
      }
    }
  }
  if (result === trimmed) {
    // "Failed sign-in (9), Successful sign-in (1)": a list of labels with counts.
    const counted = /^[^,()]+ \(\d+\)(, [^,()]+ \(\d+\))*$/
    if (counted.test(trimmed)) {
      result = trimmed
        .split(', ')
        .map((part) => {
          const match = /^(.*) (\(\d+\))$/.exec(part)
          return match ? `${translate(match[1], language)} ${match[2]}` : part
        })
        .join(', ')
    }
  }
  if (result === trimmed) return value
  return value.replace(trimmed, result)
}

export function startAutoTranslate(language: Language): () => void {
  if (language !== 'tr' || typeof document === 'undefined') return () => undefined
  const texts = new Map<Text, Shown>()
  const attributes = new Map<Element, Map<string, Shown>>()

  const skipped = (node: Node): boolean => {
    for (let parent = node.parentElement; parent; parent = parent.parentElement) {
      if (SKIP_TAGS.has(parent.tagName) || parent.hasAttribute('data-no-translate')) return true
    }
    return false
  }

  const handleText = (node: Text) => {
    if (skipped(node)) return
    const current = node.nodeValue ?? ''
    const known = texts.get(node)
    if (known && known.shown === current) return
    const next = translateString(current, 'tr')
    if (next !== current) {
      texts.set(node, { english: current, shown: next })
      node.nodeValue = next
    } else if (known) {
      texts.delete(node)
    }
  }

  const handleAttributes = (element: Element) => {
    if (skipped(element)) return
    for (const name of ATTRIBUTES) {
      const current = element.getAttribute(name)
      if (!current) continue
      const known = attributes.get(element)?.get(name)
      if (known && known.shown === current) continue
      const next = translateString(current, 'tr')
      if (next !== current) {
        const forElement = attributes.get(element) ?? new Map<string, Shown>()
        forElement.set(name, { english: current, shown: next })
        attributes.set(element, forElement)
        element.setAttribute(name, next)
      }
    }
  }

  const walk = (root: Node) => {
    if (root.nodeType === Node.TEXT_NODE) {
      handleText(root as Text)
      return
    }
    if (root.nodeType !== Node.ELEMENT_NODE) return
    handleAttributes(root as Element)
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT)
    let node = walker.nextNode()
    while (node) {
      if (node.nodeType === Node.TEXT_NODE) handleText(node as Text)
      else handleAttributes(node as Element)
      node = walker.nextNode()
    }
  }

  walk(document.body)
  const observer = new MutationObserver((records) => {
    observer.disconnect()
    texts.forEach((_, node) => {
      if (!node.isConnected) texts.delete(node)
    })
    attributes.forEach((_, element) => {
      if (!element.isConnected) attributes.delete(element)
    })
    for (const record of records) {
      if (record.type === 'characterData') handleText(record.target as Text)
      else if (record.type === 'attributes') handleAttributes(record.target as Element)
      else record.addedNodes.forEach(walk)
    }
    observe()
  })
  const observe = () =>
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ATTRIBUTES,
    })
  observe()

  return () => {
    observer.disconnect()
    texts.forEach((record, node) => {
      if (node.isConnected && node.nodeValue === record.shown) node.nodeValue = record.english
    })
    attributes.forEach((names, element) => {
      names.forEach((record, name) => {
        if (element.getAttribute(name) === record.shown) element.setAttribute(name, record.english)
      })
    })
  }
}
