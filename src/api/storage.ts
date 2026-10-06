export function readJson<T>(key: string): T | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(key);
    return stored ? (JSON.parse(stored) as T) : null;
  } catch {
    return null;
  }
}

export function writeJson(key: string, value: unknown) {
  window.localStorage.setItem(key, JSON.stringify(value));
}

export function readText(key: string) {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(key);
}

export function writeText(key: string, value: string) {
  window.localStorage.setItem(key, value);
}

export function removeKey(key: string) {
  window.localStorage.removeItem(key);
}
