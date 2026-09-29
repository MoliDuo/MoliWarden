import { notFound } from "../../http/errors";
import type { Executor } from "../../platform/db";
import { listAttachments } from "../attachments/repo";
import {
  FULL_ACCESS,
  fullAccessOrgIds,
  grantedCollectionIds,
  orgCipherAccess,
  type CipherAccess,
  type OrgContext,
} from "../organizations/access";
import { listCipherCollections } from "../organizations/repo";
import type { Cipher } from "./model";
import { findCiphers, listCiphers, listUserStates } from "./repo";
import { cipherJson } from "./responses";

// A cipher as one user sees it: an organization cipher carries that user's
// folder, favorite and archive state, and the user's rights to it.
export interface CipherView {
  cipher: Cipher;
  access: CipherAccess;
}

export const canEdit = (view: CipherView) =>
  view.access.edit || view.access.manage;

// The views of the ciphers the user can see among those given; the others
// are left out.
async function viewsOf(
  db: Executor,
  ctx: OrgContext,
  ciphers: Cipher[],
): Promise<CipherView[]> {
  const orgCipherIds = ciphers
    .filter((cipher) => cipher.organizationId)
    .map((cipher) => cipher.id);
  const [links, states] = await Promise.all([
    listCipherCollections(db, orgCipherIds),
    listUserStates(
      db,
      ctx.userId,
      ciphers.map((cipher) => cipher.id),
    ),
  ]);
  const views: CipherView[] = [];
  for (const cipher of ciphers) {
    const access = cipher.organizationId
      ? orgCipherAccess(ctx, cipher.organizationId, links.get(cipher.id) ?? [])
      : cipher.userId === ctx.userId
        ? FULL_ACCESS
        : null;
    if (!access) continue;
    views.push({ cipher: { ...cipher, ...states.get(cipher.id) }, access });
  }
  return views;
}

// Everything in the user's vault, most recently changed first.
export async function listViews(
  db: Executor,
  ctx: OrgContext,
): Promise<CipherView[]> {
  const ciphers = await listCiphers(db, {
    userId: ctx.userId,
    orgIds: fullAccessOrgIds(ctx),
    collectionIds: grantedCollectionIds(ctx),
  });
  return viewsOf(db, ctx, ciphers);
}

export async function loadViews(
  db: Executor,
  ctx: OrgContext,
  ids: string[],
): Promise<CipherView[]> {
  return viewsOf(db, ctx, await findCiphers(db, ids));
}

// A cipher the user cannot see does not exist for them.
export async function requireView(
  db: Executor,
  ctx: OrgContext,
  id: string,
): Promise<CipherView> {
  const [view] = await loadViews(db, ctx, [id]);
  if (!view) throw notFound("Cipher not found");
  return view;
}

export async function viewsJson(db: Executor, views: CipherView[]) {
  const attachments = await listAttachments(
    db,
    views.map((view) => view.cipher.id),
  );
  return views.map((view) =>
    cipherJson(view.cipher, view.access, attachments.get(view.cipher.id)),
  );
}

export async function viewJson(db: Executor, view: CipherView) {
  const [json] = await viewsJson(db, [view]);
  return json;
}
