export function redactWindowsCollectorError(value: unknown) {
  let text = value instanceof Error ? value.message : String(value)
  text = text.replace(/(password|token|secret|credential|authorization|securestring)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
  text = text.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1[REDACTED]@')
  return text.slice(0, 2048)
}
