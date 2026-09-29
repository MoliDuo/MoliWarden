// Converts a backup archive of the earlier version into today's format, so
// the web vault can restore it.
//
//   npm run backup:convert-v1 -- <old.zip> [<output directory>]
//
// The result is written next to the input unless a directory is given.
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { BackupFormatError, convertBackupArchive } from './legacy/backup';
import { printReport } from './legacy/report';

const [input, outputDir] = process.argv.slice(2);
if (!input) {
  console.error('Usage: npm run backup:convert-v1 -- <old.zip> [<output directory>]');
  process.exit(2);
}

try {
  const { archive, report } = await convertBackupArchive(new Uint8Array(await readFile(input)));
  const output = join(outputDir ?? dirname(input), archive.fileName);
  await writeFile(output, archive.bytes);
  console.log(`Wrote ${output}`);
  for (const [kind, count] of Object.entries(archive.manifest.counts)) console.log(`  ${kind}: ${count}`);
  printReport(report);
} catch (error) {
  if (!(error instanceof BackupFormatError)) throw error;
  console.error(error.message);
  process.exitCode = 1;
}
