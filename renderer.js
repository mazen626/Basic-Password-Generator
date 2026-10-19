const LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
const UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const Numbers = "0123456789";
const Symbols = "!@#$%^&*()_+[]{}|;:,.<>?";
const IDLE_REPORT_INTERVAL = 30000;

const output = document.getElementById("output");
const lengthInput = document.getElementById("length");
const siteInput = document.getElementById("site");
const masterPasswordInput = document.getElementById("masterPassword");
const confirmationInput = document.getElementById("confirmMasterPassword");
const confirmationField = document.getElementById("confirmationField");
const unlockHeading = document.getElementById("unlockHeading");
const unlockButton = document.getElementById("unlockButton");
const unlockPanel = document.getElementById("unlockPanel");
const vaultPanel = document.getElementById("vaultPanel");
const unlockStatus = document.getElementById("unlockStatus");
const vaultStatus = document.getElementById("vaultStatus");
const entriesList = document.getElementById("entriesList");
const includeLowercase = document.getElementById("includeLowercase");
const includeUppercase = document.getElementById("includeUppercase");
const includeNumbers = document.getElementById("includeNumbers");
const includeSymbols = document.getElementById("includeSymbols");
let lastActivityReport = 0;

function getRequiredCharacterSets() {
  const sets = [];
  if (includeLowercase.checked) sets.push(LowercaseLetters);
  if (includeUppercase.checked) sets.push(UppercaseLetters);
  if (includeNumbers.checked) sets.push(Numbers);
  if (includeSymbols.checked) sets.push(Symbols);
  return sets;
}

function randomInt(max) {
  const range = 2 ** 32;
  if (!Number.isInteger(max) || max < 1 || max > range) {
    throw new RangeError("max must be an integer between 1 and 2^32.");
  }
  const limit = range - (range % max);
  let randomNumber;
  do {
    randomNumber = crypto.getRandomValues(new Uint32Array(1))[0];
  } while (randomNumber >= limit);
  return randomNumber % max;
}

function createRandomChar(pool) {
  return pool.charAt(randomInt(pool.length));
}

function generatePassword(length) {
  const sets = getRequiredCharacterSets();
  const requiredCount = sets.length;
  const pool = sets.join("");
  const chars = sets.map(createRandomChar);

  for (let i = requiredCount; i < length; i++) {
    chars.push(createRandomChar(pool));
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

function validateLength() {
  const value = Number.parseInt(lengthInput.value, 10);
  const minimumLength = getRequiredCharacterSets().length;

  if (minimumLength === 0) {
    lengthInput.setCustomValidity("Select at least one character set.");
    return null;
  }
  if (!Number.isInteger(value) || value < 1 || value > 256) {
    lengthInput.setCustomValidity("Length must be between 1 and 256.");
    return null;
  }
  if (value < minimumLength) {
    lengthInput.setCustomValidity(`Length must be at least ${minimumLength} for the selected character sets.`);
    return null;
  }
  lengthInput.setCustomValidity("");
  return value;
}

function makeButton(label, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

async function refreshEntries() {
  const result = await window.electronAPI.loadEntries();
  if (!result.success) throw new Error(result.error);
  entriesList.replaceChildren();
  result.entries.forEach((entry) => entriesList.append(renderEntry(entry)));
}

function renderEntry(entry) {
  const item = document.createElement("li");
  const site = document.createElement("strong");
  const password = document.createElement("span");
  const actions = document.createElement("div");
  let revealed = false;

  site.textContent = entry.site;
  password.textContent = "••••••••••";
  actions.className = "entry-actions";
  actions.append(
    makeButton("Reveal", () => {
      revealed = !revealed;
      password.textContent = revealed ? entry.password : "••••••••••";
      actions.querySelector("button").textContent = revealed ? "Hide" : "Reveal";
    }),
    makeButton("Copy", async () => {
      const result = await window.electronAPI.copyPassword(entry.password);
      vaultStatus.textContent = result.success ? "Copied. Clipboard clears after 20 seconds." : result.error;
    }),
    makeButton("Edit", () => renderEntryEditor(entry, item)),
    makeButton("Delete", async () => {
      if (!confirm(`Delete the saved entry for ${entry.site}?`)) return;
      const result = await window.electronAPI.deleteEntry(entry.id);
      if (!result.success) {
        vaultStatus.textContent = result.error;
        return;
      }
      await refreshEntries();
      vaultStatus.textContent = "Entry deleted.";
    })
  );

  item.append(site, password, actions);
  return item;
}

function renderEntryEditor(entry, item) {
  const form = document.createElement("form");
  const siteField = document.createElement("div");
  const siteLabel = document.createElement("label");
  const site = document.createElement("input");
  const passwordField = document.createElement("div");
  const passwordLabel = document.createElement("label");
  const password = document.createElement("input");
  const actions = document.createElement("div");

  siteLabel.textContent = "Site or account";
  site.type = "text";
  site.maxLength = 200;
  site.value = entry.site;
  passwordLabel.textContent = "Password";
  password.type = "password";
  password.maxLength = 4096;
  password.value = entry.password;
  siteField.className = "field";
  passwordField.className = "field";
  actions.className = "entry-actions";
  siteField.append(siteLabel, site);
  passwordField.append(passwordLabel, password);
  actions.append(
    makeButton("Save changes", async () => {
      const result = await window.electronAPI.updateEntry(entry.id, {
        site: site.value.trim(),
        password: password.value
      });
      if (!result.success) {
        vaultStatus.textContent = result.error;
        return;
      }
      await refreshEntries();
      vaultStatus.textContent = "Entry updated.";
    }),
    makeButton("Cancel", () => item.replaceWith(renderEntry(entry)))
  );
  form.addEventListener("submit", (event) => event.preventDefault());
  form.append(siteField, passwordField, actions);
  item.replaceChildren(form);
}

async function initializeUnlockForm() {
  const result = await window.electronAPI.getVaultStatus();
  if (!result.success) {
    unlockStatus.textContent = result.error;
    return;
  }

  confirmationField.hidden = result.exists;
  confirmationInput.required = !result.exists;
  unlockHeading.textContent = result.exists ? "Unlock vault" : "Create vault";
  unlockButton.textContent = result.exists ? "Unlock vault" : "Create vault";
  masterPasswordInput.autocomplete = result.exists ? "current-password" : "new-password";
}

function clearUnlockedView(message) {
  entriesList.replaceChildren();
  output.textContent = "Click generate to start";
  siteInput.value = "";
  unlockPanel.classList.remove("hidden");
  vaultPanel.classList.add("hidden");
  unlockStatus.textContent = message;
  vaultStatus.textContent = "";
  masterPasswordInput.focus();
  initializeUnlockForm();
}

document.getElementById("unlockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  unlockStatus.textContent = "Unlocking...";

  const masterPassword = masterPasswordInput.value;
  const confirmation = confirmationInput.value;
  if (!confirmationField.hidden && masterPassword !== confirmation) {
    unlockStatus.textContent = "The master passwords do not match.";
    confirmationInput.focus();
    return;
  }

  const result = await window.electronAPI.unlockVault(masterPassword, confirmation);
  masterPasswordInput.value = "";
  confirmationInput.value = "";

  if (!result.success) {
    unlockStatus.textContent = result.error;
    return;
  }

  unlockPanel.classList.add("hidden");
  vaultPanel.classList.remove("hidden");
  vaultStatus.textContent = result.created ? "Vault created and unlocked." : "Vault unlocked.";
  lastActivityReport = 0;

  try {
    await refreshEntries();
  } catch (error) {
    vaultStatus.textContent = error.message;
  }
});

document.getElementById("lockBtn").addEventListener("click", async () => {
  const result = await window.electronAPI.lockVault();
  if (result.success) clearUnlockedView("Vault locked.");
});

window.electronAPI.onAutoLock(() => clearUnlockedView("Vault auto-locked after five minutes of inactivity."));

document.addEventListener("pointerdown", reportActivity, { passive: true });
document.addEventListener("keydown", reportActivity);
document.addEventListener("wheel", reportActivity, { passive: true });
document.addEventListener("touchstart", reportActivity, { passive: true });

function reportActivity() {
  if (vaultPanel.classList.contains("hidden")) return;
  const now = Date.now();
  if (now - lastActivityReport < IDLE_REPORT_INTERVAL) return;
  lastActivityReport = now;
  window.electronAPI.recordActivity();
}

lengthInput.addEventListener("input", validateLength);
[includeLowercase, includeUppercase, includeNumbers, includeSymbols].forEach((checkbox) => {
  checkbox.addEventListener("change", validateLength);
});

document.getElementById("generateBtn").addEventListener("click", () => {
  const length = validateLength();
  if (length === null) {
    lengthInput.reportValidity();
    return;
  }
  output.textContent = generatePassword(length);
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  if (output.textContent === "Click generate to start") return;
  const result = await window.electronAPI.copyPassword(output.textContent);
  vaultStatus.textContent = result.success ? "Copied. Clipboard clears after 20 seconds." : result.error;
});

document.getElementById("saveButton").addEventListener("click", async () => {
  const password = output.textContent;
  const site = siteInput.value.trim();

  if (!site || site.length > 200) {
    siteInput.setCustomValidity("Enter a site name up to 200 characters.");
    siteInput.reportValidity();
    return;
  }
  siteInput.setCustomValidity("");

  if (!password.trim() || password === "Click generate to start") {
    alert("Generate a password before saving.");
    return;
  }

  const result = await window.electronAPI.saveEntry({ site, password });
  if (!result.success) {
    vaultStatus.textContent = result.error;
    return;
  }

  siteInput.value = "";
  vaultStatus.textContent = "Entry saved to the encrypted vault.";
  await refreshEntries();
});

siteInput.addEventListener("input", () => siteInput.setCustomValidity(""));
initializeUnlockForm();
