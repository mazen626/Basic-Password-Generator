const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');

ipcMain.handle('save-output', async (event, content) => {
  if (typeof content !== 'string') {
    return {
      saved: false,
      canceled: false,
      error: 'Output must be text.'
    };
  }

  try {
    const ownerWindow = BrowserWindow.fromWebContents(event.sender);
    const options = {
      title: 'Save Password',
      defaultPath: 'password.txt',
      filters: [{ name: 'Text Files', extensions: ['txt'] },
                { name: 'JSON Files', extensions: ['json'] }]
    };

    const { canceled, filePath } = ownerWindow
      ? await dialog.showSaveDialog(ownerWindow, options)
      : await dialog.showSaveDialog(options);

    if (canceled || !filePath) {
      return { saved: false, canceled: true };
    }

    await fs.writeFile(filePath, content, 'utf8');
    return { saved: true, canceled: false, filePath };
  } catch (error) {
    return {
      saved: false,
      canceled: false,
      error: error.message
    };
  }
});

function createWindow() {
  const win = new BrowserWindow({
    width: 480,
    height: 640,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, 'page.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
