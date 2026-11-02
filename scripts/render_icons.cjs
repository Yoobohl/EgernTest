// 将保存的 SVG 快照渲染为透明 PNG，并记录来源和内容校验值。
// 仅处理 source/icons/sources.json 中的图标，不覆盖手动添加的其他图标。
// 准备依赖：pnpm --dir .cache/icon-renderer add @resvg/resvg-js@2.6.2
// 执行：node scripts/render_icons.cjs

/**
 * @typedef {Object} IconSource
 * @property {string} name SVG 文件名，相对于 source/icons/svg。
 * @property {string} source 上游托管地址。
 * @property {string} url 用于记录来源的原始下载地址。
 */

/**
 * @typedef {Object} RenderedIcon
 * @property {string} name 生成的 PNG 文件名。
 * @property {string} source 原始 SVG 下载地址。
 * @property {string} svg_sha256 SVG 内容的 SHA256。
 * @property {string} png_sha256 PNG 内容的 SHA256。
 * @property {number} width 像素宽度。
 * @property {number} height 像素高度。
 * @property {number} color_type PNG IHDR 颜色类型；6 表示 RGBA。
 * @property {number} bit_depth 每通道位深；本项目固定为 8。
 * @property {string} renderer 渲染器及固定版本。
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const { Resvg } = require(path.join(root, '.cache/icon-renderer/node_modules/@resvg/resvg-js'));
/** @type {IconSource[]} */
const sources = JSON.parse(fs.readFileSync(path.join(root, 'source/icons/sources.json'), 'utf8'));
const output = path.join(root, 'icons');
fs.mkdirSync(output, { recursive: true });
/** @type {RenderedIcon[]} */
const manifest = [];
for (const source of sources) {
  const svg = fs.readFileSync(path.join(root, 'source/icons/svg', source.name));
  /** @type {string[]} */
  const fontFiles = [];
  // 固定字体文件，避免不同机器自动回退字体导致文字和 PNG 校验值变化。
  if (source.name === 'nsfw_diamond.svg') {
    const fontPath = process.env.RESVG_FONT || path.join(process.env.WINDIR || 'C:\\Windows', 'Fonts/ariblk.ttf');
    if (!fs.existsSync(fontPath)) throw new Error('Set RESVG_FONT to an Arial Black font file for the NSFW icon.');
    fontFiles.push(fontPath);
  }
  const renderer = new Resvg(svg, {
    // 透明画布不额外填底色；SVG 本身已有的背景形状仍会保留。
    background: 'rgba(0,0,0,0)',
    fitTo: { mode: 'width', value: 256 },
    font: { loadSystemFonts: false, fontFiles },
  });
  const rendered = renderer.render();
  const png = rendered.asPng();
  // PNG 签名占 8 字节；IHDR 的 bit depth / color type 位于偏移 24 / 25。
  // 检查实际字节，确保渲染器输出 8-bit RGBA，而非只相信文件扩展名。
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
