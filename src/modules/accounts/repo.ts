import type { Executor } from '../../platform/db';

export async function countUsers(db: Executor): Promise<number> {
  const row = await db.selectFrom('users').select((eb) => eb.fn.countAll<number>().as('count')).executeTakeFirstOrThrow();
  return Number(row.count);
}
