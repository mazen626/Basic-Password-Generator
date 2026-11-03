// Renders build/icon-source.html into build/icon.png (1024px) and build/icon.ico.
// Run with: npm run icon
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = path.join(ROOT, 'build');
const ICO_SIZES = [16, 24, 32, 48, 64, 128, 256];
const FONT_PATH = path.join(ROOT, 'node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-700-normal.woff2');

function buildIco(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length + 16 * images.length;
  const entries = images.map(({ size, data }) => {
    const entry = Buffer.alloc(16);
    entry.writeUInt8(size >= 256 ? 0 : size, 0);
    entry.writeUInt8(size >= 256 ? 0 : size, 1);
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(data.length, 8);
    entry.writeUInt32LE(offset, 12);
    offset += data.length;
    return entry;
  });
  return Buffer.concat([header, ...entries, ...images.map(({ data }) => data)]);
}

app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  const source = fs.readFileSync(path.join(BUILD_DIR, 'icon-source.html'), 'utf8');
  const renderPath = path.join(BUILD_DIR, '.icon-render.html');
  fs.writeFileSync(renderPath, source.replace('FONT_URL', pathToFileURL(FONT_PATH).href));

  try {
    const win = new BrowserWindow({
      width: 1024, height: 1024, show: false, transparent: true, frame: false,
      webPreferences: { offscreen: true, zoomFactor: 1 }
    });
    await win.loadFile(renderPath);
    await win.webContents.executeJavaScript('document.fonts.ready');
    await new Promise((resolve) => setTimeout(resolve, 500));
    let image = await win.webContents.capturePage();
    if (image.getSize().width !== 1024) image = image.resize({ width: 1024, height: 1024, quality: 'best' });

    fs.writeFileSync(path.join(BUILD_DIR, 'icon.png'), image.toPNG());
    const icoImages = ICO_SIZES.map((size) => ({ size, data: image.resize({ width: size, height: size, quality: 'best' }).toPNG() }));
    fs.writeFileSync(path.join(BUILD_DIR, 'icon.ico'), buildIco(icoImages));
    console.log(`Wrote build/icon.png and build/icon.ico (${ICO_SIZES.join(', ')} px)`);
  } finally {
    fs.rmSync(renderPath, { force: true });
    app.quit();
  }
});
