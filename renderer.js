
  const Letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const Numbers = "0123456789";
  const Symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

  const output = document.getElementById("output");
  const lengthInput = document.getElementById("length");
  const includeNumbers = document.getElementById("includeNumbers");
  const includeSymbols = document.getElementById("includeSymbols");

  function getRequiredCharacterSets() {
    const sets = [Letters];

    if (includeNumbers.checked) {
      sets.push(Numbers);
    }
    if (includeSymbols.checked) {
      sets.push(Symbols);
    }

    return sets;
  }

  function createRandomChar(pool) {
    const max = 2 ** 32;
    const limit = max - (max % pool.length);
    let randomNumber;

    do {
      randomNumber = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (randomNumber >= limit);

    return pool.charAt(randomNumber % pool.length);
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
      const j = Math.floor(Math.random() * (i + 1));
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join("");
  }

  function validateLength() {
    const value = Number.parseInt(lengthInput.value, 10);
    const minimumLength = getRequiredCharacterSets().length;

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

  [includeNumbers, includeSymbols].forEach((checkbox) => {
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