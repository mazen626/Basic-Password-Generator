const { app, BrowserWindow, clipboard, dialog, ipcMain, powerMonitor, session, shell } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const PasswordVault = require('./vault');
const { registerCsvHandlers } = require('./csv-transfer');
const { createIpcHandlers, denyAllPermissions } = require('./ipc-handlers');

const PAGE_PATH = path.join(__dirname, 'page.html');
const PAGE_URL = pathToFileURL(PAGE_PATH).href;
const TITLE_BAR_HEIGHT = 36;
const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

let vault;

const ipc = createIpcHandlers({
  ipcMain,
  getVault: () => vault,
  pageUrl: PAGE_URL,
  clipboard,
  dialog,
  shell,
  getFocusedWindow: () => BrowserWindow.getFocusedWindow(),
  getAllWindows: () => BrowserWindow.getAllWindows(),
  getWindowFor: (contents) => BrowserWindow.fromWebContents(contents),
  quit: () => app.quit()
});
ipc.registerAll();

// CSV import and export (File menu). See csv-transfer.js.
registerCsvHandlers({
  registerVaultHandler: ipc.registerVaultHandler,
  getVault: () => vault,
  getParentWindow: () => BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0] ?? null,
  dialog,
  getDefaultDirectory: () => app.getPath('downloads'),
  onActivity: ipc.armIdleLock
});

function createWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 760,
    title: 'VLAUTR',
    icon: path.join(__dirname, 'build', 'icon.ico'),
    backgroundColor: '#05050b',
    titleBarStyle: 'hidden',
    titleBarOverlay: process.platform === 'darwin' ? true : { color: '#0b0b16', symbolColor: '#c9c3ff', height: TITLE_BAR_HEIGHT },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  // Keep the default menu's keyboard shortcuts but draw our own themed menu bar in page.html.
  if (process.platform !== 'darwin') win.setMenuBarVisibility(false);
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, navigationUrl) => {
    if (navigationUrl !== PAGE_URL) event.preventDefault();
  });
  win.loadFile(PAGE_PATH);
  win.on('closed', () => ipc.shutDown());
}

app.whenReady().then(() => {
  if (!hasSingleInstanceLock) return;
  denyAllPermissions(session.defaultSession);
  powerMonitor.on('resume', ipc.lockIfIdle);
  powerMonitor.on('unlock-screen', ipc.lockIfIdle);
  vault = new PasswordVault(path.join(app.getPath('userData'), 'vault.json'));
  createWindow();

  app.on('second-instance', () => {
    const [win] = BrowserWindow.getAllWindows();
    if (!win) return;
    if (win.isMinimized()) win.restore();
    win.show();
    win.focus();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => ipc.shutDown({ clearClipboard: true }));

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
