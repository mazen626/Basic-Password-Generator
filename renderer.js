const LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
const UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const Numbers = "0123456789";
const Symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

const output = document.getElementById("output");
const lengthInput = document.getElementById("length");
const siteInput = document.getElementById("site");
const masterPasswordInput = document.getElementById("masterPassword");
const unlockPanel = document.getElementById("unlockPanel");
const vaultPanel = document.getElementById("vaultPanel");
const unlockStatus = document.getElementById("unlockStatus");
const vaultStatus = document.getElementById("vaultStatus");
const entriesList = document.getElementById("entriesList");
const includeLowercase = document.getElementById("includeLowercase");
const includeUppercase = document.getElementById("includeUppercase");
const includeNumbers = document.getElementById("includeNumbers");
const includeSymbols = document.getElementById("includeSymbols");

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

async function refreshEntries() {
  const result = await window.electronAPI.loadEntries();
  if (!result.success) throw new Error(result.error);

  entriesList.replaceChildren();
  result.entries.forEach((entry) => {
    const item = document.createElement("li");
    const site = document.createElement("strong");
    const password = document.createElement("span");
    site.textContent = entry.site;
    password.textContent = entry.password;
    item.append(site, password);
    entriesList.append(item);
  });
}

document.getElementById("unlockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  unlockStatus.textContent = "Unlocking...";
  const result = await window.electronAPI.unlockVault(masterPasswordInput.value);
  masterPasswordInput.value = "";

  if (!result.success) {
    unlockStatus.textContent = result.error;
    return;
  }

  unlockPanel.classList.add("hidden");
  vaultPanel.classList.remove("hidden");
  vaultStatus.textContent = result.created ? "Vault created and unlocked." : "Vault unlocked.";

  try {
    await refreshEntries();
  } catch (error) {
    vaultStatus.textContent = error.message;
  }
});

document.getElementById("lockBtn").addEventListener("click", async () => {
  await window.electronAPI.lockVault();
  entriesList.replaceChildren();
  output.textContent = "Click generate to start";
  unlockPanel.classList.remove("hidden");
  vaultPanel.classList.add("hidden");
  unlockStatus.textContent = "Vault locked.";
  vaultStatus.textContent = "";
  masterPasswordInput.focus();
});

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

document.getElementById("copyBtn").addEventListener("click", () => {
  if (output.textContent !== "Click generate to start") {
    navigator.clipboard.writeText(output.textContent);
  }
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
