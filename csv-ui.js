(() => {
  const vaultPanel = document.getElementById('vaultPanel');
  const menuItems = [...document.querySelectorAll('[data-csv]')];
  const SHOWN_ROWS = 20;
  let busy = false;

  const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const report = el('dialog', 'csv-report');
  report.setAttribute('aria-labelledby', 'csvReportTitle');
  document.body.append(report);

  function showReport({ title, summary, lines = [], rowsTitle, rows = [], warning }) {
    const heading = el('h2', '', title);
    heading.id = 'csvReportTitle';
    const closeForm = el('form', 'csv-report-actions');
    closeForm.method = 'dialog';
    const closeButton = el('button', 'primary-button', 'Close');
    closeButton.type = 'submit';
    closeForm.append(closeButton);

    const parts = [heading, el('p', 'csv-report-summary', summary)];
    if (lines.length) {
      const list = el('ul', 'csv-report-list');
      lines.forEach((line) => list.append(el('li', '', line)));
      parts.push(list);
    }
    if (rows.length) {
      const list = el('ul', 'csv-report-list csv-report-rows');
      rows.forEach((row) => list.append(el('li', '', row)));
      parts.push(el('p', 'csv-report-subtitle', rowsTitle), list);
    }
    if (warning) parts.push(el('p', 'csv-report-warning', warning));
    parts.push(closeForm);

    report.replaceChildren(...parts);
    if (!report.open) report.showModal();
    closeButton.focus();
  }

  function closeReport() {
    if (report.open) report.close();
    report.replaceChildren();
  }

  function showImportReport(result) {
    const lines = [];
    if (result.duplicates) lines.push(`${count(result.duplicates, 'entry was', 'entries were')} already in your vault and skipped.`);
    if (result.renamed) lines.push(`${count(result.renamed, 'entry was', 'entries were')} renamed (the username was added) to tell accounts on the same site apart.`);
    if (result.ignoredColumns.length) lines.push(`Columns not imported: ${result.ignoredColumns.join(', ')}.`);
    if (result.backupName) lines.push('An encrypted backup of your vault was made first.');
    if (result.csvDeleted) lines.push('The CSV file was deleted.');

    const rows = result.problems.slice(0, SHOWN_ROWS).map(({ row, reason }) => `Row ${row}: ${reason}`);
    if (result.problemCount > SHOWN_ROWS) rows.push(`...and ${result.problemCount - SHOWN_ROWS} more.`);

    showReport({
      title: 'Import finished',
      summary: result.added === 0 ? 'Nothing new to import.' : `Imported ${count(result.added, 'entry', 'entries')}.`,
      lines,
      rowsTitle: `${count(result.problemCount, 'row was', 'rows were')} skipped:`,
      rows,
      warning: result.csvDeleted ? undefined : 'The CSV file still holds your passwords as plain text. Delete it when you are done.'
    });
  }

  function showExportReport(result) {
    showReport({
      title: 'Export finished',
      summary: `Exported ${count(result.count, 'entry', 'entries')} to ${result.fileName}.`,
      warning: 'This file is not encrypted: anyone who can open it can read your passwords. Delete it as soon as you are done with it.'
    });
  }

  const actions = {
    import: { run: () => window.electronAPI.importCsv(), cancelled: 'Import cancelled.', show: showImportReport },
    export: { run: () => window.electronAPI.exportCsv(), cancelled: 'Export cancelled.', show: showExportReport }
  };

  function syncMenuState() {
    const locked = vaultPanel.classList.contains('hidden');
    menuItems.forEach((item) => { item.disabled = locked || busy; });
    if (locked) closeReport();
  }

  async function runAction(name) {
    const action = actions[name];
    if (busy || !action) return;
    busy = true;
    syncMenuState();
    try {
      const result = await action.run();
      if (result.cancelled) {
        setVaultStatus(action.cancelled);
      } else if (!result.success) {
        setVaultStatus(result.error);
      } else {
        action.show(result);
        if (name === 'import') await refreshEntries();
      }
    } catch (error) {
      setVaultStatus(error.message);
    } finally {
      busy = false;
      syncMenuState();
    }
  }

  menuItems.forEach((item) => {
    item.addEventListener('click', () => {
      closeMenus();
      runAction(item.dataset.csv);
    });
  });
  new MutationObserver(syncMenuState).observe(vaultPanel, { attributes: true, attributeFilter: ['class'] });
  syncMenuState();
})();
