# Basic Password Generator (BPG)

![Electron](https://img.shields.io/badge/Built%20with-Electron-47848F?style=flat&logo=electron&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat&logo=windows&logoColor=white)

A lightweight password generator, packaged as a standalone Windows desktop app with Electron — no browser tab, no install wizard, just double-click and go.

## Features

- Generates secure, random passwords
- Runs as its own desktop app window rather than in a browser

## Requirements

- [Node.js](https://nodejs.org) installed (this also installs `npm` for you)

## Setup

1. **Download** the ZIP of this repo and **extract** it anywhere you like — just remember where.

2. **Open a terminal** (Command Prompt) and move into the extracted folder:
   ```
   cd "path\to\extracted\folder"
   ```

3. **Check your setup.** Both of these should print a version number:
   ```
   node -v
   npm -v
   ```
   If either fails, install [Node.js](https://nodejs.org) first — `npm` comes bundled with it.

4. **Install the build tool:**
   ```
   npm install --save-dev electron-builder
   ```

5. **Build the app:**
   ```
   npm run dist
   ```

6. **Grab your `.exe`.** Once the build finishes, open the new `dist` folder inside your extracted project — the `.exe` is waiting there, ready to run.

## Built With

- [Electron](https://www.electronjs.org/)
- HTML, CSS, JavaScript
