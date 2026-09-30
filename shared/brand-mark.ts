// The key mark used as the app icon, favicon and in-app logo. Stroke geometry
// on a 24x24 grid, drawn horizontally and rotated 45 degrees.
// scripts/generate-icons.ts renders the static icons from it; BrandMark.tsx
// draws it inline so it follows the theme colour.
export const BRAND_MARK = {
  viewBox: '0 0 24 24',
  transform: 'rotate(45 12 12)',
  strokeWidth: 2,
  bow: { cx: 7.5, cy: 12, r: 4.5 },
  bit: 'M12 12h9.5M18.5 12v3.5M21.5 12v2.5',
} as const;

export function brandMarkSvg(options: {
  color: string;
  darkColor?: string;
  size?: number;
  background?: string;
  padding?: number;
  radius?: number;
  strokeWidth?: number;
}): string {
  const { color, darkColor, background, padding = 0, radius = 0 } = options;
  const box = 24 + padding * 2;
  const size = options.size ?? box;
  const bg = background
    ? `<rect x="${-padding}" y="${-padding}" width="${box}" height="${box}" rx="${radius}" fill="${background}"/>`
    : '';
  const { bow, bit, transform } = BRAND_MARK;
  const strokeWidth = options.strokeWidth ?? BRAND_MARK.strokeWidth;
  const dark = darkColor ? `<style>@media (prefers-color-scheme: dark){g{stroke:${darkColor}}}</style>` : '';
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${-padding} ${-padding} ${box} ${box}">` +
    dark +
    bg +
    `<g transform="${transform}" fill="none" stroke="${color}" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round">` +
    `<circle cx="${bow.cx}" cy="${bow.cy}" r="${bow.r}"/><path d="${bit}"/></g></svg>`
  );
}
