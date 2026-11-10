const LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
const UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const Numbers = "0123456789";
const Symbols = "!@#$%^&*()_+[]{}|;:,.<>?";
const IDLE_REPORT_INTERVAL = 30000;
const STATUS_CLEAR_MS = 5000;
const OUTPUT_PLACEHOLDER = "Click generate to start";
const CATEGORY_LABELS = { login: "Login", email: "Email", finance: "Finance", identity: "Identity", work: "Work", other: "Other" };

const output = document.getElementById("output");
const strengthLabel = document.getElementById("strength");
const saveButton = document.getElementById("saveButton");
const lengthInput = document.getElementById("length");
const siteInput = document.getElementById("site");
const masterPasswordInput = document.getElementById("masterPassword");
const confirmationInput = document.getElementById("confirmMasterPassword");
const confirmationField = document.getElementById("confirmationField");
const unlockHeading = document.getElementById("unlockHeading");
const unlockButton = document.getElementById("unlockButton");
const recoveryActions = document.getElementById("recoveryActions");
const recoveryNotice = document.getElementById("recoveryNotice");
const unlockPanel = document.getElementById("unlockPanel");
const vaultPanel = document.getElementById("vaultPanel");
const unlockStatus = document.getElementById("unlockStatus");
const vaultStatus = document.getElementById("vaultStatus");
const entriesList = document.getElementById("entriesList");
const searchInput = document.getElementById("entrySearch");
const categoryFilter = document.getElementById("categoryFilter");
const favoriteFilter = document.getElementById("favoriteFilter");
const includeLowercase = document.getElementById("includeLowercase");
const includeUppercase = document.getElementById("includeUppercase");
const includeNumbers = document.getElementById("includeNumbers");
const includeSymbols = document.getElementById("includeSymbols");
let lastActivityReport = 0;
let savedEntries = [];
let searchTimer;
let statusTimer;
let editorCount = 0;
const newEntryCodes = createBackupCodeInput("new");
document.getElementById("backupCodesField").append(newEntryCodes.element);

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

function setVaultStatus(message) {
  clearTimeout(statusTimer);
  vaultStatus.textContent = message || "";
  if (message) statusTimer = setTimeout(() => { vaultStatus.textContent = ""; }, STATUS_CLEAR_MS);
}

function hasGeneratedPassword() {
  return !output.classList.contains("is-empty");
}

function setOutput(password) {
  output.classList.toggle("is-empty", !password);
  output.textContent = password || OUTPUT_PLACEHOLDER;
  updateStrength(password);
}

function updateStrength(password) {
  if (!password) {
    strengthLabel.textContent = "Ready to create";
    delete strengthLabel.dataset.level;
    return;
  }
  const poolSize = getRequiredCharacterSets().join("").length;
  const bits = password.length * Math.log2(Math.max(poolSize, 1));
  const level = bits >= 80 ? "strong" : bits >= 50 ? "fair" : "weak";
  strengthLabel.dataset.level = level;
  strengthLabel.textContent = level === "strong" ? "Strong" : level === "fair" ? "Fair" : "Weak";
}

async function withDisabled(button, task) {
  if (button.disabled) return;
  button.disabled = true;
  try {
    return await task();
  } finally {
    button.disabled = false;
  }
}

function makeButton(label, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function showDuplicateSiteError(input, message) {
  if (typeof message !== "string" || !message.toLowerCase().includes("already exists")) return false;
  input.setCustomValidity(message);
  input.reportValidity();
  return true;
}

// Copying an entry sends only its ID; the main process reads the password itself.
async function copyEntryWithConfirmation(entryId) {
  const confirmation = await window.electronAPI.confirmEntryCopy(entryId);
  if (!confirmation.success) return confirmation;
  return window.electronAPI.copyEntryPassword(entryId, confirmation.token);
}

async function copyGeneratedWithConfirmation(password) {
  const confirmation = await window.electronAPI.confirmGeneratedCopy();
  if (!confirmation.success) return confirmation;
  return window.electronAPI.copyGeneratedPassword(password, confirmation.token);
}

function describeCopy(result) {
  return result.success ? "Copied. Clipboard clears after 10 seconds." : result.cancelled ? "Copy cancelled." : result.error;
}

async function refreshEntries() {
  const result = await window.electronAPI.loadEntries();
  if (!result.success) throw new Error(result.error);
  savedEntries = Array.isArray(result.entries) ? result.entries : [];
  renderEntries();
}

function renderEntries() {
  entriesList.replaceChildren();
  const searchTerm = searchInput.value.trim().toLocaleLowerCase();
  const selectedCategory = categoryFilter.value;
  const filteredEntries = savedEntries.filter((entry) => {
    if (!entry || typeof entry !== "object") return false;
    const searchableFields = [entry.site, entry.username, entry.notes, entry.category]
      .filter((value) => typeof value === "string")
      .map((value) => value.toLocaleLowerCase());
    const matchesSearch = searchableFields.some((value) => value.includes(searchTerm));
    const category = typeof entry.category === "string" ? entry.category : "";
    const matchesCategory = selectedCategory === "all" || category === selectedCategory;
    const matchesFavorite = !favoriteFilter.checked || entry.favorite === true;
    return matchesSearch && matchesCategory && matchesFavorite;
  });
  filteredEntries.sort((first, second) => {
    const favoriteOrder = Number(second.favorite === true) - Number(first.favorite === true);
    const firstSite = typeof first.site === "string" ? first.site : "";
    const secondSite = typeof second.site === "string" ? second.site : "";
    return favoriteOrder || firstSite.localeCompare(secondSite);
  });
  if (filteredEntries.length === 0) {
    const emptyState = document.createElement("li");
    emptyState.className = "empty-state";
    emptyState.textContent = savedEntries.length ? "No entries match these filters." : "No saved entries yet.";
    entriesList.append(emptyState);
    return;
  }
  filteredEntries.forEach((entry) => entriesList.append(renderEntry(entry)));
}

function renderEntry(entry) {
  const savedEntry = entry && typeof entry === "object" ? entry : {};
  const item = document.createElement("li");
  const header = document.createElement("div");
  const site = document.createElement("strong");
  const details = document.createElement("span");
  const password = document.createElement("span");
  const actions = document.createElement("div");
  // A revealed password lives only here, until it is hidden or this card is replaced.
  let revealedPassword = null;

  const siteName = typeof savedEntry.site === "string" ? savedEntry.site : "Unknown site";
  const username = typeof savedEntry.username === "string" ? savedEntry.username : "";
  const category = CATEGORY_LABELS[savedEntry.category] || "Uncategorized";
  const canUsePassword = savedEntry.hasPassword === true && typeof savedEntry.id === "string";
  site.textContent = `${savedEntry.favorite === true ? "★ " : ""}${siteName}`;
  details.textContent = `${category} · ${username || "No username"}`;
  details.className = "entry-detail";
  header.className = "entry-card-head";
  header.append(site, details);
  password.textContent = "••••••••••";
  password.className = "entry-password";
  actions.className = "entry-actions";
  const revealButton = makeButton("Reveal", () => withDisabled(revealButton, async () => {
    if (revealedPassword !== null) {
      revealedPassword = null;
      password.textContent = "••••••••••";
      revealButton.textContent = "Reveal";
      return;
    }
    const result = await window.electronAPI.revealPassword(savedEntry.id);
    if (!item.isConnected) return;
    if (!result.success) {
      setVaultStatus(result.error);
      return;
    }
    revealedPassword = result.password;
    password.textContent = revealedPassword;
    revealButton.textContent = "Hide";
  }));
  const copyButton = makeButton("Copy", async () => {
    setVaultStatus(describeCopy(await copyEntryWithConfirmation(savedEntry.id)));
  });
  revealButton.disabled = !canUsePassword;
  copyButton.disabled = !canUsePassword;
  actions.append(revealButton, copyButton);
  if (typeof savedEntry.id === "string") {
    const deleteButton = makeButton("Delete", () => withDisabled(deleteButton, async () => {
      if (!confirm(`Delete the saved entry for ${siteName}?`)) return;
      const result = await window.electronAPI.deleteEntry(savedEntry.id);
      if (!result.success) {
        setVaultStatus(result.error);
        return;
      }
      try {
        await refreshEntries();
        setVaultStatus("Entry deleted.");
      } catch (error) {
        setVaultStatus(error.message);
      }
    }));
    deleteButton.className = "danger-button";
    const editButton = makeButton("Edit", () => withDisabled(editButton, () => openEntryEditor(savedEntry, item)));
    actions.append(editButton, deleteButton);
  }

  const codes = renderEntryCodes(savedEntry);
  item.append(header, password);
  if (codes) item.append(codes);
  item.append(actions);
  return item;
}

function createBackupCodeInput(idPrefix, existingCodes = []) {
  const element = document.createElement("div");
  const label = document.createElement("label");
  const textarea = document.createElement("textarea");
  const splitLabel = document.createElement("label");
  const splitOnSpaces = document.createElement("input");
  const summary = document.createElement("small");
  const problem = document.createElement("small");
  const preview = document.createElement("ul");
  let keptCodes = existingCodes.map(({ code, used }) => ({ code, used }));

  function getNewCodes() {
    const kept = new Set(keptCodes.map(({ code }) => code));
    return parseBackupCodes(textarea.value, { splitOnSpaces: splitOnSpaces.checked }).filter((code) => !kept.has(code));
  }

  function getCodes() {
    return [...keptCodes.map(({ code }) => code), ...getNewCodes()];
  }

  function getProblem() {
    return findBackupCodeProblem(getCodes());
  }

  function makePreviewItem(code, used, position, onRemove) {
    const item = document.createElement("li");
    const value = document.createElement("span");
    const removeButton = makeButton("×", onRemove);
    value.className = used ? "backup-code-value backup-code-used" : "backup-code-value";
    value.textContent = code;
    removeButton.setAttribute("aria-label", `Remove code ${position}`);
    item.append(value);
    if (used) {
      const tag = document.createElement("span");
      tag.className = "backup-code-tag";
      tag.textContent = "used";
      item.append(tag);
    }
    item.append(removeButton);
    return item;
  }

  function render() {
    const newCodes = getNewCodes();
    const total = keptCodes.length + newCodes.length;
    summary.textContent = total ? `${total} code${total === 1 ? "" : "s"}` : "";
    problem.textContent = getProblem();
    preview.replaceChildren(
      ...keptCodes.map(({ code, used }, index) => makePreviewItem(code, used, index + 1, () => {
        keptCodes = keptCodes.filter((kept) => kept.code !== code);
        render();
      })),
      ...newCodes.map((code, index) => makePreviewItem(code, false, keptCodes.length + index + 1, () => {
        textarea.value = newCodes.filter((newCode) => newCode !== code).join("\n");
        render();
      }))
    );
  }

  function reset() {
    textarea.value = "";
    splitOnSpaces.checked = true;
    keptCodes = [];
    render();
  }

  element.className = "field backup-code-input";
  textarea.id = `${idPrefix}-backup-codes`;
  textarea.placeholder = "Paste your backup codes";
  textarea.maxLength = 20000;
  textarea.spellcheck = false;
  textarea.autocomplete = "off";
  textarea.addEventListener("input", render);
  label.htmlFor = textarea.id;
  label.textContent = "Backup codes";
  splitOnSpaces.type = "checkbox";
  splitOnSpaces.checked = true;
  splitOnSpaces.addEventListener("change", render);
  splitLabel.className = "check";
  splitLabel.append(splitOnSpaces, document.createTextNode(" Split on spaces"));
  problem.className = "backup-code-problem";
  preview.className = "backup-code-grid";
  element.append(label, textarea, splitLabel, summary, problem, preview);
  render();
  return { element, getCodes, getProblem, reset };
}

// The card shows only the counts. The codes themselves are fetched when "Show codes" is pressed,
// and dropped again on "Hide codes" or when the card is replaced.
function renderEntryCodes(savedEntry) {
  const counts = savedEntry.backupCodes && typeof savedEntry.backupCodes === "object" ? savedEntry.backupCodes : null;
  if (!counts || !(counts.total > 0) || typeof savedEntry.id !== "string") return null;

  const section = document.createElement("div");
  const heading = document.createElement("div");
  const summary = document.createElement("span");
  const list = document.createElement("ul");
  let shown = false;

  function updateSummary() {
    summary.textContent = `Backup codes: ${counts.unused} of ${counts.total} unused`;
  }

  function renderCode(code) {
    const item = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    const value = document.createElement("span");
    label.className = "check";
    checkbox.type = "checkbox";
    checkbox.checked = code.used;
    value.textContent = code.code;
    value.classList.toggle("backup-code-used", code.used);
    checkbox.addEventListener("change", async () => {
      checkbox.disabled = true;
      const result = await window.electronAPI.setBackupCodeUsed(savedEntry.id, code.id, checkbox.checked);
      checkbox.disabled = false;
      if (!result.success) {
        checkbox.checked = code.used;
        setVaultStatus(result.error);
        return;
      }
      if (code.used !== checkbox.checked) counts.unused += checkbox.checked ? -1 : 1;
      code.used = checkbox.checked;
      value.classList.toggle("backup-code-used", code.used);
      updateSummary();
    });
    label.append(checkbox, value);
    item.append(label);
    return item;
  }

  const toggleButton = makeButton("Show codes", () => withDisabled(toggleButton, async () => {
    if (shown) {
      shown = false;
      list.replaceChildren();
      list.hidden = true;
      toggleButton.textContent = "Show codes";
      return;
    }
    const result = await window.electronAPI.getBackupCodes(savedEntry.id);
    if (!section.isConnected) return;
    if (!result.success) {
      setVaultStatus(result.error);
      return;
    }
    shown = true;
    counts.total = result.codes.length;
    counts.unused = result.codes.filter((code) => !code.used).length;
    list.replaceChildren(...result.codes.map(renderCode));
    list.hidden = false;
    toggleButton.textContent = "Hide codes";
    updateSummary();
  }));
  section.className = "entry-codes";
  heading.className = "backup-code-summary";
  list.className = "backup-code-grid";
  list.hidden = true;
  heading.append(summary, toggleButton);
  section.append(heading, list);
  updateSummary();
  return section;
}

// Fetches the entry's backup codes (if it has any) before showing the edit form.
// The password is not fetched unless "Show" is pressed in the form.
async function openEntryEditor(entry, item) {
  let codes = [];
  if (entry.backupCodes?.total > 0) {
    const result = await window.electronAPI.getBackupCodes(entry.id);
    if (!result.success) {
      setVaultStatus(result.error);
      return;
    }
    codes = result.codes;
  }
  if (!item.isConnected) return;
  renderEntryEditor(entry, item, codes);
}

function renderEntryEditor(entry, item, existingCodes) {
  const form = document.createElement("form");
  const siteField = document.createElement("div");
  const siteLabel = document.createElement("label");
  const site = document.createElement("input");
  const usernameField = document.createElement("div");
  const usernameLabel = document.createElement("label");
  const username = document.createElement("input");
  const notesField = document.createElement("div");
  const notesLabel = document.createElement("label");
  const notes = document.createElement("textarea");
  const categoryField = document.createElement("div");
  const categoryLabel = document.createElement("label");
  const category = document.createElement("select");
  const favoriteField = document.createElement("label");
  const favorite = document.createElement("input");
  const passwordField = document.createElement("div");
  const passwordLabel = document.createElement("label");
  const password = document.createElement("input");
  const actions = document.createElement("div");
  const idPrefix = `edit-${++editorCount}`;
  const backupCodes = createBackupCodeInput(idPrefix, existingCodes);

  [[siteLabel, site, "site"], [usernameLabel, username, "username"], [passwordLabel, password, "password"], [notesLabel, notes, "notes"], [categoryLabel, category, "category"]]
    .forEach(([label, control, name]) => {
      control.id = `${idPrefix}-${name}`;
      label.htmlFor = control.id;
    });
  siteLabel.textContent = "Site or account";
  site.type = "text";
  site.maxLength = 200;
  site.value = entry.site ?? "";
  site.addEventListener("input", () => site.setCustomValidity(""));
  usernameLabel.textContent = "Username";
  username.type = "text";
  username.maxLength = 255;
  username.value = entry.username ?? "";
  notesLabel.textContent = "Notes";
  notes.maxLength = 4000;
  notes.value = entry.notes ?? "";
  categoryLabel.textContent = "Category";
  ["login", "email", "finance", "identity", "work", "other"].forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value[0].toUpperCase() + value.slice(1);
    category.append(option);
  });
  category.value = CATEGORY_LABELS[entry.category] ? entry.category : "other";
  favorite.type = "checkbox";
  favorite.checked = entry.favorite === true;
  favoriteField.className = "check";
  favoriteField.append(favorite, document.createTextNode(" Favorite"));
  passwordLabel.textContent = "Password";
  password.type = "password";
  password.maxLength = 4096;
  password.value = "";
  password.placeholder = "Leave blank to keep the current password";
  password.autocomplete = "off";
  const passwordRow = document.createElement("div");
  passwordRow.className = "password-row";
  const showPasswordButton = makeButton("Show", () => withDisabled(showPasswordButton, async () => {
    if (password.type === "text") {
      password.type = "password";
      showPasswordButton.textContent = "Show";
      return;
    }
    if (password.value === "") {
      const result = await window.electronAPI.revealPassword(entry.id);
      if (!form.isConnected) return;
      if (!result.success) {
        setVaultStatus(result.error);
        return;
      }
      password.value = result.password;
    }
    password.type = "text";
    showPasswordButton.textContent = "Hide";
  }));
  passwordRow.append(password, showPasswordButton);
  siteField.className = "field";
  passwordField.className = "field";
  actions.className = "entry-actions";
  siteField.append(siteLabel, site);
  usernameField.className = "field";
  usernameField.append(usernameLabel, username);
  notesField.className = "field";
  notesField.append(notesLabel, notes);
  categoryField.className = "field";
  categoryField.append(categoryLabel, category);
  passwordField.append(passwordLabel, passwordRow);
  const saveChangesButton = makeButton("Save changes", () => withDisabled(saveChangesButton, async () => {
      const codeProblem = backupCodes.getProblem();
      if (codeProblem) {
        setVaultStatus(codeProblem);
        return;
      }
      const changes = {
        site: site.value.trim(),
        username: username.value,
        notes: notes.value,
        category: category.value,
        favorite: favorite.checked,
        backupCodes: backupCodes.getCodes()
      };
      // A blank password field keeps the saved password.
      if (password.value !== "") changes.password = password.value;
      const result = await window.electronAPI.updateEntry(entry.id, changes);
      if (!result.success) {
        showDuplicateSiteError(site, result.error);
        setVaultStatus(result.error);
        return;
      }
      try {
        await refreshEntries();
        setVaultStatus("Entry updated.");
      } catch (error) {
        setVaultStatus(error.message);
      }
    }));
  saveChangesButton.className = "primary-button";
  actions.append(saveChangesButton, makeButton("Cancel", () => item.replaceWith(renderEntry(entry))));
  form.addEventListener("submit", (event) => event.preventDefault());
  form.append(siteField, usernameField, passwordField, notesField, backupCodes.element, categoryField, favoriteField, actions);
  item.replaceChildren(form);
  site.focus();
}

async function initializeUnlockForm() {
  const result = await window.electronAPI.getVaultStatus();
  if (!result.success) {
    unlockStatus.textContent = result.error;
    return;
  }

  confirmationField.hidden = result.exists;
  confirmationInput.required = !result.exists;
  recoveryActions.classList.toggle("hidden", !result.exists);
  recoveryNotice.textContent = result.corrupted
    ? "The vault file appears damaged or unsupported. It has not been changed. Create an encrypted backup before trying recovery."
    : result.legacy
      ? "This older vault will be upgraded after unlock. An encrypted backup is created automatically before migration; you can also create one now."
      : result.exists
        ? "You can create an encrypted backup or open the vault folder before unlocking."
        : "";
  unlockHeading.textContent = result.exists ? "Unlock vault" : "Create vault";
  unlockButton.textContent = result.exists ? "Unlock vault" : "Create vault";
  masterPasswordInput.autocomplete = result.exists ? "current-password" : "new-password";
}

function clearUnlockedView(message) {
  closeChangePasswordDialog();
  entriesList.replaceChildren();
  savedEntries = [];
  searchInput.value = "";
  categoryFilter.value = "all";
  favoriteFilter.checked = false;
  setOutput("");
  siteInput.value = "";
  siteInput.setCustomValidity("");
  document.getElementById("username").value = "";
  document.getElementById("notes").value = "";
  newEntryCodes.reset();
  document.getElementById("category").value = "login";
  document.getElementById("favorite").checked = false;
  unlockPanel.classList.remove("hidden");
  vaultPanel.classList.add("hidden");
  unlockStatus.textContent = message;
  setVaultStatus("");
  masterPasswordInput.focus();
  initializeUnlockForm();
}

document.getElementById("unlockForm").addEventListener("submit", (event) => {
  event.preventDefault();
  withDisabled(unlockButton, unlockVault);
});

async function unlockVault() {
  const masterPassword = masterPasswordInput.value;
  const confirmation = confirmationInput.value;
  if (!confirmationField.hidden && masterPassword !== confirmation) {
    unlockStatus.textContent = "The master passwords do not match.";
    confirmationInput.focus();
    return;
  }

  unlockStatus.textContent = confirmationField.hidden ? "Unlocking..." : "Creating vault...";
  const result = await window.electronAPI.unlockVault(masterPassword, confirmation);
  masterPasswordInput.value = "";
  confirmationInput.value = "";

  if (!result.success) {
    const error = typeof result.error === "string" ? result.error : "Could not unlock the vault.";
    unlockStatus.textContent = error.includes("Incorrect master password or vault data is corrupted.")
      ? "The password may be incorrect, or the vault may be damaged. The file was not changed; create an encrypted backup before recovery."
      : error;
    return;
  }

  unlockPanel.classList.add("hidden");
  vaultPanel.classList.remove("hidden");
  unlockStatus.textContent = "";
  setVaultStatus(result.migrated ? "Vault upgraded and unlocked." : result.created ? "Vault created and unlocked." : "Vault unlocked.");
  lastActivityReport = 0;

  try {
    await refreshEntries();
  } catch (error) {
    setVaultStatus(error.message);
  }
}

document.getElementById("lockBtn").addEventListener("click", async () => {
  const result = await window.electronAPI.lockVault();
  if (result.success) clearUnlockedView("Vault locked.");
  else setVaultStatus(result.error);
});

document.getElementById("backupVaultBtn").addEventListener("click", async () => {
  const result = await window.electronAPI.backupVault();
  recoveryNotice.textContent = result.success
    ? `Encrypted backup created: ${result.backupName}`
    : result.error;
});

document.getElementById("openVaultFolderBtn").addEventListener("click", async () => {
  const result = await window.electronAPI.openVaultFolder();
  if (!result.success) recoveryNotice.textContent = result.error;
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
  checkbox.addEventListener("change", () => {
    validateLength();
    if (hasGeneratedPassword()) setOutput("");
  });
});

document.getElementById("generateBtn").addEventListener("click", () => {
  const length = validateLength();
  if (length === null) {
    lengthInput.reportValidity();
    return;
  }
  setOutput(generatePassword(length));
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  if (!hasGeneratedPassword()) {
    setVaultStatus("Generate a password before copying.");
    return;
  }
  setVaultStatus(describeCopy(await copyGeneratedWithConfirmation(output.textContent)));
});

saveButton.addEventListener("click", () => withDisabled(saveButton, saveNewEntry));

async function saveNewEntry() {
  const password = output.textContent;
  const site = siteInput.value.trim();
  const username = document.getElementById("username").value;
  const notes = document.getElementById("notes").value;
  const category = document.getElementById("category").value;
  const favorite = document.getElementById("favorite").checked;

  if (!site || site.length > 200) {
    siteInput.setCustomValidity("Enter a site name up to 200 characters.");
    siteInput.reportValidity();
    return;
  }
  siteInput.setCustomValidity("");

  if (!hasGeneratedPassword() || !password.trim()) {
    setVaultStatus("Generate a password before saving.");
    return;
  }

  const codeProblem = newEntryCodes.getProblem();
  if (codeProblem) {
    setVaultStatus(codeProblem);
    return;
  }

  const backupCodes = newEntryCodes.getCodes();
  const result = await window.electronAPI.saveEntry({ site, username, password, notes, category, favorite, backupCodes });
  if (!result.success) {
    showDuplicateSiteError(siteInput, result.error);
    setVaultStatus(result.error);
    return;
  }

  siteInput.value = "";
  document.getElementById("username").value = "";
  document.getElementById("notes").value = "";
  newEntryCodes.reset();
  document.getElementById("favorite").checked = false;
  setOutput("");
  setVaultStatus("Entry saved to the encrypted vault.");
  try {
    await refreshEntries();
  } catch (error) {
    setVaultStatus(error.message);
  }
}

siteInput.addEventListener("input", () => siteInput.setCustomValidity(""));
searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(renderEntries, 200);
});
categoryFilter.addEventListener("change", renderEntries);
favoriteFilter.addEventListener("change", renderEntries);

const menuTriggers = [...document.querySelectorAll(".menu-trigger")];
const lockMenuItem = document.querySelector('[data-action="lock"]');
const changePasswordMenuItem = document.getElementById("changePasswordMenuItem");

function menuListFor(trigger) {
  return document.getElementById(trigger.getAttribute("aria-controls"));
}

function closeMenus() {
  menuTriggers.forEach((trigger) => {
    trigger.setAttribute("aria-expanded", "false");
    menuListFor(trigger).hidden = true;
  });
}

function openMenu(trigger, focusFirst = false) {
  closeMenus();
  lockMenuItem.disabled = vaultPanel.classList.contains("hidden");
  changePasswordMenuItem.disabled = vaultPanel.classList.contains("hidden");
  trigger.setAttribute("aria-expanded", "true");
  const list = menuListFor(trigger);
  list.hidden = false;
  if (focusFirst) list.querySelector("button:not(:disabled)")?.focus();
}

function openMenuTrigger() {
  return menuTriggers.find((trigger) => trigger.getAttribute("aria-expanded") === "true");
}

document.body.classList.add(`platform-${window.electronAPI.platform}`);

// Keep focus in the page's text fields so Edit actions apply to them.
document.querySelector(".titlebar").addEventListener("mousedown", (event) => {
  if (event.target.closest("button")) event.preventDefault();
});

menuTriggers.forEach((trigger, index) => {
  trigger.addEventListener("click", (event) => {
    if (trigger.getAttribute("aria-expanded") === "true") closeMenus();
    else openMenu(trigger, event.detail === 0);
  });
  trigger.addEventListener("mouseenter", () => {
    const openTrigger = openMenuTrigger();
    if (openTrigger && openTrigger !== trigger) openMenu(trigger);
  });
  menuListFor(trigger).addEventListener("keydown", (event) => {
    const items = [...menuListFor(trigger).querySelectorAll("button:not(:disabled)")];
    const position = items.indexOf(document.activeElement);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      items[(position + step + items.length) % items.length]?.focus();
    } else if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      event.preventDefault();
      const step = event.key === "ArrowRight" ? 1 : -1;
      openMenu(menuTriggers[(index + step + menuTriggers.length) % menuTriggers.length], true);
    }
  });
});

// Change master password (File menu). The form's values are cleared whenever it closes.
const changePasswordDialog = document.getElementById("changePasswordDialog");
const changePasswordForm = document.getElementById("changePasswordForm");
const changePasswordFields = ["currentMasterPassword", "newMasterPassword", "confirmNewMasterPassword"].map((id) => document.getElementById(id));
const changePasswordStatus = document.getElementById("changePasswordStatus");
const changePasswordSubmit = document.getElementById("changePasswordSubmit");

function clearChangePasswordForm() {
  changePasswordFields.forEach((field) => { field.value = ""; });
  changePasswordStatus.textContent = "";
}

function closeChangePasswordDialog() {
  if (changePasswordDialog.open) changePasswordDialog.close();
  clearChangePasswordForm();
}

changePasswordDialog.addEventListener("close", clearChangePasswordForm);
document.getElementById("changePasswordCancel").addEventListener("click", closeChangePasswordDialog);

changePasswordMenuItem.addEventListener("click", () => {
  closeMenus();
  if (vaultPanel.classList.contains("hidden")) return;
  clearChangePasswordForm();
  changePasswordDialog.showModal();
  changePasswordFields[0].focus();
});

changePasswordForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const [current, next, confirmation] = changePasswordFields;
  if (next.value !== confirmation.value) {
    changePasswordStatus.textContent = "The new passwords do not match.";
    confirmation.focus();
    return;
  }
  withDisabled(changePasswordSubmit, async () => {
    changePasswordStatus.textContent = "Changing the master password...";
    const result = await window.electronAPI.changeMasterPassword(current.value, next.value, confirmation.value);
    if (!changePasswordDialog.open) return;
    if (!result.success) {
      changePasswordStatus.textContent = result.error;
      (result.error.includes("current master password") ? current : next).select();
      return;
    }
    closeChangePasswordDialog();
    setVaultStatus("Master password changed. Your previous backups still need the old password.");
  });
});

document.querySelectorAll(".menu-list [data-action]").forEach((item) => {
  item.addEventListener("click", async () => {
    const { action } = item.dataset;
    closeMenus();
    if (action === "lock") {
      if (!vaultPanel.classList.contains("hidden")) document.getElementById("lockBtn").click();
      return;
    }
    await window.electronAPI.menuAction(action);
  });
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".menu")) closeMenus();
});
document.addEventListener("keydown", (event) => {
  const trigger = openMenuTrigger();
  if (event.key !== "Escape" || !trigger) return;
  closeMenus();
  trigger.focus();
});
window.addEventListener("blur", closeMenus);
initializeUnlockForm();
