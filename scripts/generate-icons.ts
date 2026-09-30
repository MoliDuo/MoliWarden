// Renders the static icons in webapp/public from the key mark in
// shared/brand-mark.ts. Run after changing the mark: npm run icons
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Resvg } from '@resvg/resvg-js';
import { brandMarkSvg } from '../shared/brand-mark';

const PUBLIC_DIR = join(process.cwd(), 'webapp', 'public');
const INK = '#0a0a0a';
const PAPER = '#ffffff';

function png(svg: string, size: number): Buffer {
  return new Resvg(svg, { fitTo: { mode: 'width', value: size } }).render().asPng();
}

// Small sizes keep a rounded tile; home-screen icons are full bleed because
// the platform applies its own mask. Padding keeps the key inside the
// maskable safe zone.
const tile = (padding: number) =>
  brandMarkSvg({ color: PAPER, background: INK, padding, radius: padding * 1.6, strokeWidth: 2.6 });
const fullBleed = (padding: number) => brandMarkSvg({ color: PAPER, background: INK, padding });

// ICO container holding PNG images (supported by every current browser).
function ico(images: Array<{ size: number; data: Buffer }>): Buffer {
  const header = Buffer.alloc(6 + images.length * 16);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach((image, index) => {
    const entry = 6 + index * 16;
    header.writeUInt8(image.size >= 256 ? 0 : image.size, entry);
    header.writeUInt8(image.size >= 256 ? 0 : image.size, entry + 1);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(image.data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += image.data.length;
  });
  return Buffer.concat([header, ...images.map((image) => image.data)]);
}

async function main(): Promise<void> {
  const files: Record<string, string | Buffer> = {
    'logo.svg': brandMarkSvg({ color: INK, darkColor: '#fafafa' }),
    'favicon.svg': tile(3),
    'favicon-32.png': png(tile(3), 32),
    'apple-touch-icon.png': png(fullBleed(6), 180),
    'icon-192.png': png(fullBleed(7), 192),
    'icon-512.png': png(fullBleed(7), 512),
    'favicon.ico': ico([16, 32, 48].map((size) => ({ size, data: png(tile(size === 16 ? 2 : 3), size) }))),
  };
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(PUBLIC_DIR, name), content);
    console.log(`wrote webapp/public/${name}`);
  }
}

void main();
