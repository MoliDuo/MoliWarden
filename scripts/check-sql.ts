// Static SQL check: finds every `.prepare(<sql>)` call, reconstructs the SQL
// text (template substitutions are replaced with sensible stand-ins) and asks
// PostgreSQL to PREPARE it against the real schema. Catches syntax errors,
// unknown columns, ambiguous references and untyped parameters.
//
//   TEST_DATABASE_URL=postgres://... npx tsx scripts/check-sql.ts
import ts from 'typescript';
import pg from 'pg';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { rewritePlaceholders } from '../src/platform/pg-d1';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPgPool, PgD1Database } from '../src/platform/pg-d1';

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith('.ts') && !full.endsWith('.d.ts')) out.push(full);
  }
  return out;
}

function substitute(expr: ts.Expression, sf: ts.SourceFile, consts: Map<string, ts.Expression>): string {
  const text = expr.getText(sf);
  if (ts.isIdentifier(expr) && consts.has(expr.text)) {
    const value = evaluate(consts.get(expr.text)!, sf, consts);
    if (value !== null) return value;
  }
  if (/placeholder/i.test(text)) return '?, ?';
  if (/Columns\(\)|COLUMNS|columns/.test(text)) return '*';
  if (/tableName|table\b|shadowTableName/i.test(text)) return '__TABLE__';
  if (/where|clause|filter|order/i.test(text)) return '';
  return `__EXPR(${text})__`;
}

function evaluate(node: ts.Expression, sf: ts.SourceFile, consts: Map<string, ts.Expression>): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isParenthesizedExpression(node)) return evaluate(node.expression, sf, consts);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = evaluate(node.left, sf, consts);
    const r = evaluate(node.right, sf, consts);
    return l === null || r === null ? null : l + r;
  }
  if (ts.isTemplateExpression(node)) {
    let out = node.head.text;
    for (const span of node.templateSpans) {
      out += substitute(span.expression, sf, consts) + span.literal.text;
    }
    return out;
  }
  if (ts.isIdentifier(node) && consts.has(node.text)) {
    return evaluate(consts.get(node.text)!, sf, consts);
  }
  if (ts.isConditionalExpression(node)) {
    return evaluate(node.whenTrue, sf, consts);
  }
  return null;
}

interface Found { file: string; line: number; sql: string | null; raw: string }

function collect(file: string): Found[] {
  const sf = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const consts = new Map<string, ts.Expression>();
  const found: Found[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      consts.set(node.name.text, node.initializer);
    }
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'prepare' &&
      node.arguments.length === 1
    ) {
      const arg = node.arguments[0];
      found.push({
        file,
        line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1,
        sql: evaluate(arg, sf, consts),
        raw: arg.getText(sf).slice(0, 120),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

async function main(): Promise<void> {
  const url = process.env.TEST_DATABASE_URL || 'postgres://mw:mw@localhost:55432/mw';
  const pool = createPgPool({ connectionString: url, max: 2 });
  const client = await pool.connect();
  await client.query('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
  await ensureStorageSchema(new PgD1Database(pool));

  const statements = walk('src').flatMap(collect);
  let failures = 0;
  let skipped = 0;
  let index = 0;
  for (const statement of statements) {
    if (statement.sql === null || statement.sql.includes('__EXPR(') || statement.sql.includes('__TABLE__')) {
      skipped++;
      console.log(`SKIP ${statement.file}:${statement.line} ${statement.sql ? statement.sql.slice(0, 140).replace(/\s+/g, ' ') : statement.raw}`);
      continue;
    }
    const sql = rewritePlaceholders(statement.sql);
    try {
      await client.query('BEGIN');
      await client.query(`PREPARE check_${index++} AS ${sql}`);
    } catch (error) {
      failures++;
      console.log(`FAIL ${statement.file}:${statement.line}\n     ${(error as Error).message}\n     ${statement.sql.replace(/\s+/g, ' ').slice(0, 300)}`);
    } finally {
      await client.query('ROLLBACK');
    }
  }
  console.log(`\n${statements.length} statements, ${failures} failed, ${skipped} skipped`);
  client.release();
  await pool.end();
  process.exit(failures ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
