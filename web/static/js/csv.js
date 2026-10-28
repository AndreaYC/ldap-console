// CSV export helpers. Pure functions: no DOM access, so they run under node --test.

// Cells starting with these are evaluated as formulas by Excel, Numbers and
// Sheets. Directory values (names, descriptions) are often user-editable.
const formulaStart = /^[=+\-@\t\r]/;

function cell(value) {
  let s = String(value ?? '');
  if (formulaStart.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replaceAll('"', '""') + '"' : s;
}

// toCSV renders a header row and data rows as CSV text.
export function toCSV(header, rows) {
  return [header, ...rows].map((r) => r.map(cell).join(',')).join('\n');
}
