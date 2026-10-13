// Rasterize the original vector icons without filling their transparent canvas.
// pnpm --dir .cache/icon-renderer add @resvg/resvg-js@2.6.2
// node scripts/render_icons.cjs
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const { Resvg } = require(path.join(root, '.cache/icon-renderer/node_modules/@resvg/resvg-js'));
const sources = JSON.parse(fs.readFileSync(path.join(root, 'source/icons/sources.json'), 'utf8'));
const output = path.join(root, 'icons');
fs.mkdirSync(output, { recursive: true });
const manifest = [];
for (const source of sources) {
  const svg = fs.readFileSync(path.join(root, 'source/icons/svg', source.name));
  const fontFiles = [];
  if (source.name === 'nsfw_diamond.svg') {
    const fontPath = process.env.RESVG_FONT || path.join(process.env.WINDIR || 'C:\\Windows', 'Fonts/ariblk.ttf');
    if (!fs.existsSync(fontPath)) throw new Error('Set RESVG_FONT to an Arial Black font file for the NSFW icon.');
    fontFiles.push(fontPath);
  }
  const renderer = new Resvg(svg, {
    background: 'rgba(0,0,0,0)',
    fitTo: { mode: 'width', value: 256 },
    font: { loadSystemFonts: false, fontFiles },
  });
  const rendered = renderer.render();
  const png = rendered.asPng();
  // IHDR color type 6 means truecolor with a dedicated alpha channel.
  if (png[24] !== 8 || png[25] !== 6) throw new Error(`Expected 8-bit RGBA: ${source.name}`);
  const name = path.basename(source.name, '.svg') + '.png';
  fs.writeFileSync(path.join(output, name), png);
  manifest.push({
    name,
    source: source.url,
    svg_sha256: crypto.createHash('sha256').update(svg).digest('hex'),
    png_sha256: crypto.createHash('sha256').update(png).digest('hex'),
    width: rendered.width,
    height: rendered.height,
    color_type: 6,
    bit_depth: 8,
    renderer: '@resvg/resvg-js@2.6.2',
  });
}
fs.writeFileSync(path.join(root, 'source/icons/manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Rendered ${manifest.length} alpha PNG icons.`);
