import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('vantage', {
  runAnalysis: (repoPath: string) => ipcRenderer.invoke('vantage:run-analysis', repoPath),
  getStatus: () => ipcRenderer.invoke('vantage:get-status'),
  setMode: (mode: 'SAFE' | 'ASSIST' | 'AUTONOMOUS') => ipcRenderer.invoke('vantage:set-mode', mode)
});