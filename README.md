# VLAUTR

VLAUTR is the current working name for this Electron password generator and encrypted local password vault.

![Electron](https://img.shields.io/badge/Built%20with-Electron-47848F?style=flat&logo=electron&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat&logo=windows&logoColor=white)

## Features

- Generate passwords with configurable length and lowercase, uppercase, number, and symbol sets.
- Create a master-password protected vault. Vault entries are encrypted locally with AES-256-GCM and a key derived using PBKDF2.
- Save site, username, password, notes, category, and favorite status for each entry.
- Search and filter entries by category or favorites, with favorites and sites sorted for quick access.
- Reveal passwords only on request; copying requires confirmation and clipboard contents are cleared after 10 seconds when possible. Other apps or clipboard history may still capture clipboard contents.
- Edit and delete entries, with duplicate sites prevented.
- Lock the vault manually or automatically after five minutes of inactivity.
- Create encrypted backups and automatically back up older vaults before migration.

## Requirements

- [Node.js](https://nodejs.org) and npm

## Run locally

```sh
npm ci
npm start
```

The app opens as a Windows desktop window. The visible window title is currently **VLAUTR** and may change.

## Build for Windows

```sh
npm run dist
```

The portable build is written to the `dist` directory.

## Built with

- [Electron](https://www.electronjs.org/)
- HTML, CSS, and JavaScript
