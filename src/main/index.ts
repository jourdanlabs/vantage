import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';

let mainWindow: BrowserWindow | null = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    backgroundColor: '#080b1a',
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));

  // Handle route for separate pages
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('page-loaded');
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers
ipcMain.handle('vantage:run-analysis', async (_event, repoPath: string) => {
  // Placeholder - real implementation will wire COSMIC engines
  return { status: 'analyzing', engines: ['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'AURORA'] };
});

ipcMain.handle('vantage:get-status', async () => {
  return { 
    version: 'v0.1.0-alpha',
    mode: 'AUTO',
    uptime: process.uptime(),
    engines: { METEOR: 'ready', NOVA: 'ready', ECLIPSE: 'ready', PULSAR: 'ready', AURORA: 'ready' }
  };
});

ipcMain.handle('vantage:set-mode', async (_event, mode: 'SAFE' | 'ASSIST' | 'AUTONOMOUS') => {
  return { mode, acknowledged: true };
});