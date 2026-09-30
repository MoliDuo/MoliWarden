import type { BackupScheduleConfig } from '../../../shared/backup-schema';
import type { Runtime } from './settings';

// When a scheduled destination is due. Its runs are slots in its time
// zone: every `intervalHours` from `startTime`, starting again each day
// (so an interval of a day or more gives one slot a day, and more than a
// day skips days until the interval has passed since the last success).
//
// The cron job may run rarely (daily on Vercel Hobby), so a destination is
// due whenever its latest slot has passed without an attempt: a missed
// slot is caught up once, however late.

const HOUR = 3_600_000;

interface LocalDate {
  year: number;
  month: number;
  day: number;
}

function localParts(date: Date, timeZone: string): LocalDate & { hour: number; minute: number } {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const pick = (type: string) => Number(parts.find((part) => part.type === type)?.value);
  return { year: pick('year'), month: pick('month'), day: pick('day'), hour: pick('hour'), minute: pick('minute') };
}

// The instant a wall-clock time in `timeZone` happens at.
function instantOf(date: LocalDate, hour: number, minute: number, timeZone: string): number {
  const wanted = Date.UTC(date.year, date.month - 1, date.day, hour, minute);
  const seen = localParts(new Date(wanted), timeZone);
  const offset = Date.UTC(seen.year, seen.month - 1, seen.day, seen.hour, seen.minute) - wanted;
  return wanted - offset;
}

function shiftDays(date: LocalDate, days: number): LocalDate {
  const shifted = new Date(Date.UTC(date.year, date.month - 1, date.day + days));
  return { year: shifted.getUTCFullYear(), month: shifted.getUTCMonth() + 1, day: shifted.getUTCDate() };
}

function slotsOf(date: LocalDate, schedule: BackupScheduleConfig): number[] {
  const [hour, minute] = schedule.startTime.split(':').map(Number);
  const first = instantOf(date, hour, minute, schedule.timezone);
  const end = instantOf(shiftDays(date, 1), 0, 0, schedule.timezone);
  const slots: number[] = [];
  for (let slot = first; slot < end; slot += schedule.intervalHours * HOUR) slots.push(slot);
  return slots;
}

// The latest slot at or before `now`.
export function latestSlot(schedule: BackupScheduleConfig, now: Date): Date {
  const today = localParts(now, schedule.timezone);
  const passed = slotsOf(today, schedule).filter((slot) => slot <= now.getTime());
  return new Date(passed.length ? passed[passed.length - 1] : slotsOf(shiftDays(today, -1), schedule).at(-1)!);
}

const time = (value: string | null) => (value ? Date.parse(value) : Number.NEGATIVE_INFINITY);

export function isDue(schedule: BackupScheduleConfig, runtime: Runtime, now: Date): boolean {
  if (!schedule.enabled) return false;
  if (time(runtime.lastAttemptAt) >= latestSlot(schedule, now).getTime()) return false;
  // An hour of slack absorbs the cron job's own delay.
  return schedule.intervalHours <= 24 || now.getTime() - time(runtime.lastSuccessAt) >= (schedule.intervalHours - 1) * HOUR;
}
