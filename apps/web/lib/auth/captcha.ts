export function normalizeCaptchaToken(value: string | null | undefined) {
  const token = value?.trim();
  return token ? token : undefined;
}

export function captchaReady(enabled: boolean, value: string | null | undefined) {
  return !enabled || Boolean(normalizeCaptchaToken(value));
}

export function captchaOptions(value: string | null | undefined) {
  const captchaToken = normalizeCaptchaToken(value);
  return captchaToken ? { captchaToken } : {};
}
