const { app, BrowserWindow, ipcMain, dialog } = require('electron');

ipcMain.handle('open-file-dialog', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ['openFile', 'multiSelections']
  });
  return canceled ? [] : filePaths;
});

const path = require('path');

function createWindow () {
  const mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      nodeIntegration: true,   // Allow require() in renderer
      contextIsolation: false  // Disable for simplicity
    }
  });
  
  if (!app.isPackaged) {
  //mainWindow.webContents.openDevTools();
} else {
  mainWindow.setMenu(null);
}

  mainWindow.loadFile('index.html');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
