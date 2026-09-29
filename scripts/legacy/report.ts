import type { Report } from './transform';

export function printReport(report: Report): void {
  if (report.skipped.length) {
    console.log(`\nLeft out (${report.skipped.length}):`);
    for (const entry of report.skipped) console.log(`  ${entry.table} ${entry.id}: ${entry.reason}`);
  }
  if (report.notices.length) {
    console.log('\nTo know:');
    for (const notice of report.notices) console.log(`  - ${notice}`);
  }
}
