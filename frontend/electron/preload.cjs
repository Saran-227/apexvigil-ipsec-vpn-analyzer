const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  isDesktop: true,
  selectPcapFile: () => ipcRenderer.invoke('dialog:openPcap'),
  getAppVersion: () => ipcRenderer.invoke('app:version')
})
