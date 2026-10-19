  const LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
  const UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const Numbers = "0123456789";
  const Symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

  const output = document.getElementById("output");
  const lengthInput = document.getElementById("length");
  const includeLowercase = document.getElementById("includeLowercase");
  const includeUppercase = document.getElementById("includeUppercase");
  const includeNumbers = document.getElementById("includeNumbers");
  const includeSymbols = document.getElementById("includeSymbols");

  function getRequiredCharacterSets() {
    const sets = [];

    if (includeLowercase.checked) {
      sets.push(LowercaseLetters);
    }
    if (includeUppercase.checked) {
      sets.push(UppercaseLetters);
    }
    if (includeNumbers.checked) {
      sets.push(Numbers);
    }
    if (includeSymbols.checked) {
      sets.push(Symbols);
    }

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
    const effectiveLength = Math.max(length, requiredCount);
    const pool = sets.join("");
    const chars = [];

    sets.forEach((set) => {
      chars.push(createRandomChar(set));
    });

    for (let i = requiredCount; i < effectiveLength; i++) {
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

  lengthInput.addEventListener("input", () => {
    const value = lengthInput.value;

    if (value === "") {
      lengthInput.setCustomValidity("Length is required.");
      return;
    }

    validateLength();
  });

  [includeLowercase, includeUppercase, includeNumbers, includeSymbols].forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      validateLength();
    });
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

document.getElementById('saveButton').addEventListener('click', async () => {
  const password = output.textContent;

  if (!password.trim() || password === 'Click generate to start') {
    alert('Generate a password before saving.');
    return;
  }

  try {
    const result = await window.electronAPI.saveOutput(password);

    if (result.canceled) return;

    if (result.error) {
      alert('Saving failed: ' + result.error);
      return;
    }

    if (result.saved) {
      alert('Password saved successfully to:\n' + result.filePath);
    }
  } catch (error) {
    alert('Could not save the password: ' + error.message);
  }
});
