"use strict";
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("kbc", {
  config: () => ipcRenderer.invoke("kbc:config"),
  quote: () => ipcRenderer.invoke("kbc:quote"),
  pay: () => ipcRenderer.invoke("kbc:pay"),
  update: () => ipcRenderer.invoke("kbc:update")
});
