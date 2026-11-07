// Turns pasted backup codes into a list. Loaded by page.html and by the tests.
const MAX_BACKUP_CODES = 50;
const MAX_BACKUP_CODE_LENGTH = 128;
const LIST_MARKER = /^(?:\(?\d{1,3}[.)]|[-*•])$/;
const LEADING_LIST_MARKER = /^(?:\(?\d{1,3}[.)]|[-*•])\s+/;

function parseBackupCodes(text, { splitOnSpaces = true } = {}) {
  const separator = splitOnSpaces ? /[\s,;]+/ : /[\r\n,;]+/;
  const codes = String(text)
    .split(separator)
    .map((code) => code.trim().replace(LEADING_LIST_MARKER, "").replace(/\s+/g, " "))
    .filter((code) => code && !LIST_MARKER.test(code));
  return [...new Set(codes)];
}

function findBackupCodeProblem(codes) {
  if (codes.length > MAX_BACKUP_CODES) return `An entry can have up to ${MAX_BACKUP_CODES} backup codes.`;
  if (codes.some((code) => code.length > MAX_BACKUP_CODE_LENGTH)) {
    return `Each backup code must be ${MAX_BACKUP_CODE_LENGTH} characters or fewer.`;
  }
  return "";
}

if (typeof module === "object" && module.exports) {
  module.exports = { MAX_BACKUP_CODES, parseBackupCodes, findBackupCodeProblem };
}
