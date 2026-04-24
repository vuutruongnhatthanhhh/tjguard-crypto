export const SPECIALS = `!@#$%^&*()-_=+[]{};:'",.<>/?\\|~\``;

export const hasLower = (s: string) => /[a-z]/.test(s);
export const hasUpper = (s: string) => /[A-Z]/.test(s);
export const hasDigit = (s: string) => /[0-9]/.test(s);

export const hasSpecial = (s: string) =>
  new RegExp("[" + SPECIALS.replace(/[-\\^$*+?.()|[\]{}]/g, "\\$&") + "]").test(
    s,
  );

export const minLen = (s: string, min = 12) => s.length >= min;

function randomFrom(str: string): string {
  return str[Math.floor(Math.random() * str.length)];
}

function shuffle(arr: string[]): string[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export function generatePassword(length = 12): string {
  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const DIGITS = "0123456789";
  const all = LOWER + UPPER + DIGITS + SPECIALS;

  const chars: string[] = [];
  chars.push(
    randomFrom(LOWER),
    randomFrom(UPPER),
    randomFrom(DIGITS),
    randomFrom(SPECIALS),
  );

  for (let i = chars.length; i < Math.max(12, length); i++) {
    chars.push(randomFrom(all));
  }

  return shuffle(chars).join("");
}
