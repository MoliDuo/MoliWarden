import { Hono, type Context } from 'hono';
import { authenticate, callerOf, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { listJson } from '../../http/list';
import { notFound } from '../../http/errors';
import { idParam } from '../../http/params';
import type { Deps } from '../../main/deps';
import {
  collectionDetails,
  collectionUsers,
  createCollection,
  deleteOrgCollections,
  myCollections,
  orgCollectionDetails,
  orgCollections,
  setCollectionsAccess,
  updateCollection,
} from './collections';
import {
  confirmMembers,
  editMember,
  inviteMembers,
  memberById,
  memberPublicKeys,
  membersJson,
  membersMiniJson,
  reinviteMember,
  removeMembers,
  setRevoked,
  single,
  type Outcome,
} from './members';
import {
  bulkAccessBody,
  bulkConfirmBody,
  collectionBody,
  confirmBody,
  createOrgBody,
  editMemberBody,
  idsBody,
  inviteBody,
  orgKeysBody,
  passwordBody,
  updateCollectionBody,
  updateOrgBody,
} from './schemas';
import {
  acceptInvitation,
  createOrganization,
  deleteOrganization,
  disabledPolicy,
  invitations,
  leaveOrganization,
  organizationById,
  organizationPublicKey,
  setOrganizationKeys,
  updateOrganization,
  userPublicKey,
} from './service';

const org = (...suffixes: string[]) => suffixes.map((suffix) => `/api/organizations/:orgId${suffix}`);
const member = (...suffixes: string[]) => org(...suffixes.map((suffix) => `/users/:memberId${suffix}`));
const collection = (...suffixes: string[]) => org(...suffixes.map((suffix) => `/collections/:collectionId${suffix}`));

const orgId = (c: Context) => idParam(c, 'orgId');
const memberId = (c: Context) => idParam(c, 'memberId');
const collectionId = (c: Context) => idParam(c, 'collectionId');

const ok = (c: Context) => c.body(null, 200);
const outcomesJson = (outcomes: Outcome[], object: string) => listJson(outcomes.map((outcome) => ({ object, ...outcome })));

export function organizationRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  app.post('/api/organizations', authed, async (c) => c.json(await createOrganization(deps, callerOf(c), await readJson(c, createOrgBody))));
  app.get('/api/organizations/invitations', authed, async (c) => c.json(listJson(await invitations(deps, callerOf(c)))));
  app.get('/api/collections', authed, async (c) => c.json(listJson(await myCollections(deps, callerOf(c)))));
  app.get('/api/users/:id/public-key', authed, async (c) => c.json(await userPublicKey(deps, idParam(c))));

  // Features this server does not have; answered so clients do not log errors.
  app.get('/api/tasks', authed, (c) => c.json(listJson([])));
  app.on('GET', ['/api/policies', ...org('/policies', '/policies/token', '/billing/metadata')], authed, (c) => c.json(listJson([])));
  app.get('/api/organizations/:orgId/policies/:type', authed, (c) => {
    const type = c.req.param('type');
    if (!/^(\d+|master-password)$/i.test(type)) throw notFound();
    return c.json(disabledPolicy(orgId(c), type));
  });
  app.get('/api/organizations/:orgId/billing/vnext/warnings', authed, (c) =>
    c.json({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null }),
  );
  app.get('/api/organizations/:orgId/billing/vnext/self-host/metadata', authed, (c) =>
    c.json({ isOnSecretsManagerStandalone: false, organizationOccupiedSeats: 0 }),
  );

  // The organization.
  app.get('/api/organizations/:orgId', authed, async (c) => c.json(await organizationById(deps, callerOf(c), orgId(c))));
  app.on(['PUT', 'POST'], org(''), authed, async (c) =>
    c.json(await updateOrganization(deps, callerOf(c), orgId(c), await readJson(c, updateOrgBody))),
  );
  const removeOrganization = async (c: Context<AuthedEnv>) => {
    await deleteOrganization(deps, callerOf(c), orgId(c), (await readJson(c, passwordBody)).masterPasswordHash);
    return ok(c);
  };
  app.delete('/api/organizations/:orgId', authed, removeOrganization);
  app.post('/api/organizations/:orgId/delete', authed, removeOrganization);
  app.post('/api/organizations/:orgId/leave', authed, async (c) => {
    await leaveOrganization(deps, callerOf(c), orgId(c));
    return ok(c);
  });
  app.on('GET', org('/keys', '/public-key'), authed, async (c) => c.json(await organizationPublicKey(deps, callerOf(c), orgId(c))));
  app.post('/api/organizations/:orgId/keys', authed, async (c) =>
    c.json(await setOrganizationKeys(deps, callerOf(c), orgId(c), await readJson(c, orgKeysBody))),
  );

  // Its members; routes on all of them come before those on one.
  app.get('/api/organizations/:orgId/users', authed, async (c) =>
    c.json(listJson(await membersJson(deps, callerOf(c), orgId(c), c.req.query('includeCollections') === 'true'))),
  );
  app.get('/api/organizations/:orgId/users/mini-details', authed, async (c) =>
    c.json(listJson(await membersMiniJson(deps, callerOf(c), orgId(c)))),
  );
  app.post('/api/organizations/:orgId/users/invite', authed, async (c) => {
    await inviteMembers(deps, callerOf(c), orgId(c), await readJson(c, inviteBody));
    return ok(c);
  });
  app.post('/api/organizations/:orgId/users/confirm', authed, async (c) => {
    const outcomes = await confirmMembers(deps, callerOf(c), orgId(c), (await readJson(c, bulkConfirmBody)).keys);
    return c.json(outcomesJson(outcomes, 'OrganizationBulkConfirmResponseModel'));
  });
  app.post('/api/organizations/:orgId/users/public-keys', authed, async (c) =>
    c.json(listJson(await memberPublicKeys(deps, callerOf(c), orgId(c), (await readJson(c, idsBody)).ids))),
  );
  app.delete('/api/organizations/:orgId/users', authed, async (c) => {
    const outcomes = await removeMembers(deps, callerOf(c), orgId(c), (await readJson(c, idsBody)).ids);
    return c.json(outcomesJson(outcomes, 'OrganizationBulkConfirmResponseModel'));
  });
  for (const [suffix, revoke] of [['revoke', true], ['restore', false]] as const) {
    app.put(`/api/organizations/:orgId/users/${suffix}`, authed, async (c) => {
      const outcomes = await setRevoked(deps, callerOf(c), orgId(c), (await readJson(c, idsBody)).ids, revoke);
      return c.json(outcomesJson(outcomes, 'OrganizationUserBulkResponseModel'));
    });
  }

  app.get('/api/organizations/:orgId/users/:memberId', authed, async (c) =>
    c.json(await memberById(deps, callerOf(c), orgId(c), memberId(c))),
  );
  app.on(['PUT', 'POST'], member(''), authed, async (c) => {
    await editMember(deps, callerOf(c), orgId(c), memberId(c), await readJson(c, editMemberBody));
    return ok(c);
  });
  const removeMember = async (c: Context<AuthedEnv>) => {
    single(await removeMembers(deps, callerOf(c), orgId(c), [memberId(c)]));
    return ok(c);
  };
  app.delete('/api/organizations/:orgId/users/:memberId', authed, removeMember);
  app.post('/api/organizations/:orgId/users/:memberId/delete', authed, removeMember);
  app.post('/api/organizations/:orgId/users/:memberId/accept', authed, async (c) => {
    await acceptInvitation(deps, callerOf(c), orgId(c), memberId(c));
    return ok(c);
  });
  app.post('/api/organizations/:orgId/users/:memberId/reinvite', authed, async (c) => {
    await reinviteMember(deps, callerOf(c), orgId(c), memberId(c));
    return ok(c);
  });
  app.post('/api/organizations/:orgId/users/:memberId/confirm', authed, async (c) => {
    const { key } = await readJson(c, confirmBody);
    single(await confirmMembers(deps, callerOf(c), orgId(c), [{ id: memberId(c), key }]));
    return ok(c);
  });
  app.put('/api/organizations/:orgId/users/:memberId/revoke', authed, async (c) => {
    single(await setRevoked(deps, callerOf(c), orgId(c), [memberId(c)], true));
    return ok(c);
  });
  app.on('PUT', member('/restore', '/restore/vnext'), authed, async (c) => {
    single(await setRevoked(deps, callerOf(c), orgId(c), [memberId(c)], false));
    return ok(c);
  });

  // Its collections.
  app.get('/api/organizations/:orgId/collections', authed, async (c) =>
    c.json(listJson(await orgCollections(deps, callerOf(c), orgId(c)))),
  );
  app.post('/api/organizations/:orgId/collections', authed, async (c) =>
    c.json(await createCollection(deps, callerOf(c), orgId(c), await readJson(c, collectionBody))),
  );
  app.delete('/api/organizations/:orgId/collections', authed, async (c) => {
    await deleteOrgCollections(deps, callerOf(c), orgId(c), (await readJson(c, idsBody)).ids);
    return ok(c);
  });
  app.get('/api/organizations/:orgId/collections/details', authed, async (c) =>
    c.json(listJson(await orgCollectionDetails(deps, callerOf(c), orgId(c)))),
  );
  app.post('/api/organizations/:orgId/collections/bulk-access', authed, async (c) => {
    const { collectionIds, users } = await readJson(c, bulkAccessBody);
    await setCollectionsAccess(deps, callerOf(c), orgId(c), collectionIds, users);
    return ok(c);
  });

  app.on(['PUT', 'POST'], collection(''), authed, async (c) =>
    c.json(await updateCollection(deps, callerOf(c), orgId(c), collectionId(c), await readJson(c, updateCollectionBody))),
  );
  const removeCollection = async (c: Context<AuthedEnv>) => {
    await deleteOrgCollections(deps, callerOf(c), orgId(c), [collectionId(c)]);
    return ok(c);
  };
  app.delete('/api/organizations/:orgId/collections/:collectionId', authed, removeCollection);
  app.post('/api/organizations/:orgId/collections/:collectionId/delete', authed, removeCollection);
  app.get('/api/organizations/:orgId/collections/:collectionId/details', authed, async (c) =>
    c.json(await collectionDetails(deps, callerOf(c), orgId(c), collectionId(c))),
  );
  app.get('/api/organizations/:orgId/collections/:collectionId/users', authed, async (c) =>
    c.json(await collectionUsers(deps, callerOf(c), orgId(c), collectionId(c))),
  );

  return app;
}
