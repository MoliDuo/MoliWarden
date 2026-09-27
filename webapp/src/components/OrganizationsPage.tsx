import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Building2, Check, Fingerprint, Layers, LogOut, Pencil, Plus, RefreshCw, Trash2, UserCheck, UserMinus, UserPlus, UserX, Users } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import LoadingState from '@/components/LoadingState';
import { t } from '@/lib/i18n';
import { base64ToBytes } from '@/lib/crypto';
import { deriveLoginHash } from '@/lib/api/auth';
import { getFingerprintPhrase } from '@/lib/api/auth-requests';
import type { AuthedFetch } from '@/lib/api/shared';
import {
  ORG_STATUS,
  ORG_TYPE,
  acceptInvitation,
  confirmMember,
  createOrganization,
  deleteCollection,
  deleteOrganization,
  editMember,
  getMemberPublicKey,
  getMyPublicKey,
  inviteMembers,
  leaveOrganization,
  listCollectionDetails,
  listInvitations,
  listMembers,
  removeMember,
  saveCollection,
  setMemberRevoked,
  updateOrganization,
  type OrgCollectionAccess,
  type OrgCollectionDetails,
  type OrgInvitation,
  type OrgMember,
} from '@/lib/api/organizations';
import { decryptWithOrgKey } from '@/lib/org-crypto';
import type { OrgKeyMap, Profile, ProfileOrganization } from '@/lib/types';

// Organization management: invitations, members, collections and settings.
// All secrets stay client-side: the org key is only ever sent wrapped with a
// member's RSA public key, and collection names are encrypted with the org key.

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface OrganizationsPageProps {
  authedFetch: AuthedFetch;
  profile: Profile | null;
  organizations: ProfileOrganization[];
  orgKeys: OrgKeyMap;
  defaultKdfIterations: number;
  onRefresh: () => Promise<void>;
  onNotify: Notify;
}

type AccessLevel = 'none' | 'view' | 'view_except' | 'edit' | 'edit_except' | 'manage';
type Tab = 'members' | 'collections' | 'settings';

const ACCESS_LEVELS: AccessLevel[] = ['none', 'view', 'view_except', 'edit', 'edit_except', 'manage'];

function accessLabel(level: AccessLevel): string {
  return t(`txt_org_access_${level}`);
}

function toAccessLevel(access: OrgCollectionAccess | undefined): AccessLevel {
  if (!access) return 'none';
  if (access.manage) return 'manage';
  if (access.readOnly) return access.hidePasswords ? 'view_except' : 'view';
  return access.hidePasswords ? 'edit_except' : 'edit';
}

function fromAccessLevel(id: string, level: AccessLevel): OrgCollectionAccess | null {
  switch (level) {
    case 'view':
      return { id, readOnly: true, hidePasswords: false, manage: false };
    case 'view_except':
      return { id, readOnly: true, hidePasswords: true, manage: false };
    case 'edit':
      return { id, readOnly: false, hidePasswords: false, manage: false };
    case 'edit_except':
      return { id, readOnly: false, hidePasswords: true, manage: false };
    case 'manage':
      return { id, readOnly: false, hidePasswords: false, manage: true };
    default:
      return null;
  }
}

function roleLabel(type: number): string {
  if (type === ORG_TYPE.OWNER) return t('txt_org_role_owner');
  if (type === ORG_TYPE.ADMIN) return t('txt_org_role_admin');
  if (type === ORG_TYPE.MANAGER || type === ORG_TYPE.CUSTOM) return t('txt_org_role_manager');
  return t('txt_org_role_user');
}

function statusLabel(status: number): string {
  if (status === ORG_STATUS.INVITED) return t('txt_org_status_invited');
  if (status === ORG_STATUS.ACCEPTED) return t('txt_org_status_accepted');
  if (status === ORG_STATUS.CONFIRMED) return t('txt_org_status_confirmed');
  return t('txt_org_status_revoked');
}

function errorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function isAdminType(type: number): boolean {
  return type === ORG_TYPE.OWNER || type === ORG_TYPE.ADMIN;
}

// Per-collection access editor used for members (by collection) and collections (by member).
function AccessMatrix(props: {
  rows: Array<{ id: string; label: string }>;
  values: Record<string, AccessLevel>;
  onChange: (id: string, level: AccessLevel) => void;
  emptyText: string;
}) {
  if (!props.rows.length) return <p className="muted-inline">{props.emptyText}</p>;
  return (
    <div className="org-access-matrix">
      {props.rows.map((row) => (
        <label key={row.id} className="org-access-row">
          <span className="org-access-label" title={row.label}>{row.label}</span>
          <select
            className="input small"
            value={props.values[row.id] || 'none'}
            onInput={(e) => props.onChange(row.id, (e.currentTarget as HTMLSelectElement).value as AccessLevel)}
          >
            {ACCESS_LEVELS.map((level) => (
              <option key={level} value={level}>{accessLabel(level)}</option>
            ))}
          </select>
        </label>
      ))}
    </div>
  );
}

export default function OrganizationsPage(props: OrganizationsPageProps) {
  const { authedFetch, orgKeys, onNotify } = props;
  const userId = String(props.profile?.id || '');
  const email = String(props.profile?.email || '');

  const [invitations, setInvitations] = useState<OrgInvitation[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState('');
  const [tab, setTab] = useState<Tab>('members');
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [collections, setCollections] = useState<OrgCollectionDetails[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [myFingerprint, setMyFingerprint] = useState('');

  // Dialog state
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createCollection, setCreateCollection] = useState('');
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmails, setInviteEmails] = useState('');
  const [memberDialog, setMemberDialog] = useState<OrgMember | null>(null);
  const [memberType, setMemberType] = useState<number>(ORG_TYPE.USER);
  const [memberAccess, setMemberAccess] = useState<Record<string, AccessLevel>>({});
  const [confirmTarget, setConfirmTarget] = useState<{ member: OrgMember; publicKey: string; phrase: string } | null>(null);
  const [removeTarget, setRemoveTarget] = useState<OrgMember | null>(null);
  const [collectionDialog, setCollectionDialog] = useState<{ id?: string } | null>(null);
  const [collectionName, setCollectionName] = useState('');
  const [collectionAccess, setCollectionAccess] = useState<Record<string, AccessLevel>>({});
  const [deleteCollectionTarget, setDeleteCollectionTarget] = useState<OrgCollectionDetails | null>(null);
  const [orgName, setOrgName] = useState('');
  const [leaveOpen, setLeaveOpen] = useState(false);
  const [deleteOrgOpen, setDeleteOrgOpen] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');

  // Organizations deleted or left from this page stay hidden, and are never
  // reloaded, while the vault refresh that drops them is still in flight.
  const [removedOrgIds, setRemovedOrgIds] = useState<string[]>([]);
  const removedOrgIdsRef = useRef<string[]>([]);
  const organizations = useMemo(
    () => props.organizations.filter((org) => !removedOrgIds.includes(org.id)),
    [props.organizations, removedOrgIds]
  );
  const selectedOrg = organizations.find((org) => org.id === selectedOrgId) || null;
  const myType = selectedOrg ? (selectedOrg.type === ORG_TYPE.CUSTOM ? ORG_TYPE.MANAGER : selectedOrg.type) : ORG_TYPE.USER;
  const canAdmin = isAdminType(myType);
  const isOwner = myType === ORG_TYPE.OWNER;
  const canManageCollections = canAdmin || myType === ORG_TYPE.MANAGER;

  useEffect(() => {
    if (!selectedOrgId && organizations.length) setSelectedOrgId(organizations[0].id);
    if (selectedOrgId && !organizations.some((org) => org.id === selectedOrgId)) {
      setSelectedOrgId(organizations[0]?.id || '');
    }
  }, [organizations, selectedOrgId]);

  useEffect(() => {
    setOrgName(selectedOrg?.name || '');
  }, [selectedOrg?.id, selectedOrg?.name]);

  async function loadInvitations() {
    try {
      setInvitations(await listInvitations(authedFetch));
    } catch (error) {
      onNotify('error', errorText(error, t('txt_org_load_failed')));
    }
  }

  function forgetOrganization(orgId: string) {
    removedOrgIdsRef.current = [...removedOrgIdsRef.current, orgId];
    setRemovedOrgIds(removedOrgIdsRef.current);
  }

  async function loadOrgData(orgId: string) {
    if (removedOrgIdsRef.current.includes(orgId)) return;
    const org = organizations.find((item) => item.id === orgId);
    if (!org) return;
    const type = org.type === ORG_TYPE.CUSTOM ? ORG_TYPE.MANAGER : org.type;
    setLoading(true);
    try {
      const [nextMembers, nextCollections] = await Promise.all([
        isAdminType(type) ? listMembers(authedFetch, orgId) : Promise.resolve([] as OrgMember[]),
        isAdminType(type) || type === ORG_TYPE.MANAGER ? listCollectionDetails(authedFetch, orgId) : Promise.resolve([] as OrgCollectionDetails[]),
      ]);
      const decrypted = await Promise.all(
        nextCollections.map(async (collection) => ({
          ...collection,
          decName: (await decryptWithOrgKey(collection.name, orgKeys, orgId)) || t('txt_org_collection_unnamed'),
        }))
      );
      setMembers(nextMembers);
      setCollections(decrypted);
    } catch (error) {
      onNotify('error', errorText(error, t('txt_org_load_failed')));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadInvitations();
  }, []);

  useEffect(() => {
    if (!userId) return;
    void getMyPublicKey(authedFetch, userId)
      .then((key) => getFingerprintPhrase(userId, base64ToBytes(key)))
      .then(setMyFingerprint)
      .catch(() => setMyFingerprint(''));
  }, [userId]);

  useEffect(() => {
    if (selectedOrgId) void loadOrgData(selectedOrgId);
    else {
      setMembers([]);
      setCollections([]);
    }
  }, [selectedOrgId, orgKeys]);

  async function run(action: () => Promise<void>, success: string, options: { refreshVault?: boolean } = {}) {
    setBusy(true);
    try {
      await action();
      if (options.refreshVault) await props.onRefresh();
      if (selectedOrgId) await loadOrgData(selectedOrgId);
      onNotify('success', success);
    } catch (error) {
      onNotify('error', errorText(error, t('txt_org_action_failed')));
      throw error;
    } finally {
      setBusy(false);
    }
  }

  const collectionRows = useMemo(
    () => collections.map((collection) => ({ id: collection.id, label: collection.decName || t('txt_org_collection_unnamed') })),
    [collections]
  );
  const memberRows = useMemo(
    () => members
      .filter((member) => !member.accessAll && member.status !== ORG_STATUS.REVOKED)
      .map((member) => ({ id: member.id, label: member.email })),
    [members]
  );

  function accessListFrom(values: Record<string, AccessLevel>): OrgCollectionAccess[] {
    return Object.entries(values)
      .map(([id, level]) => fromAccessLevel(id, level))
      .filter((entry): entry is OrgCollectionAccess => !!entry);
  }

  function openMemberDialog(member: OrgMember | null) {
    setMemberDialog(member);
    setMemberType(member ? member.type : ORG_TYPE.USER);
    setMemberAccess(Object.fromEntries((member?.collections || []).map((access) => [access.id, toAccessLevel(access)])));
    if (!member) {
      setInviteEmails('');
      setInviteOpen(true);
    }
  }

  async function startConfirm(member: OrgMember) {
    if (!selectedOrgId) return;
    setBusy(true);
    try {
      const { key, userId: memberUserId } = await getMemberPublicKey(authedFetch, selectedOrgId, member.id);
      const phrase = await getFingerprintPhrase(memberUserId, base64ToBytes(key));
      setConfirmTarget({ member, publicKey: key, phrase });
    } catch (error) {
      onNotify('error', errorText(error, t('txt_org_action_failed')));
    } finally {
      setBusy(false);
    }
  }

  function openCollectionDialog(collection: OrgCollectionDetails | null) {
    setCollectionDialog(collection ? { id: collection.id } : {});
    setCollectionName(collection?.decName || '');
    setCollectionAccess(Object.fromEntries((collection?.users || []).map((access) => [access.id, toAccessLevel(access)])));
  }

  const roleOptions = isOwner
    ? [ORG_TYPE.USER, ORG_TYPE.MANAGER, ORG_TYPE.ADMIN, ORG_TYPE.OWNER]
    : [ORG_TYPE.USER];

  return (
    <div className="stack org-page">
      {invitations.length > 0 && (
        <section className="card">
          <div className="section-head">
            <h3>{t('txt_org_pending_invitations')}</h3>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>{t('txt_org_organization')}</th>
                <th>{t('txt_org_invited_by')}</th>
                <th>{t('txt_status')}</th>
                <th>{t('txt_actions')}</th>
              </tr>
            </thead>
            <tbody>
              {invitations.map((invitation) => (
                <tr key={invitation.id}>
                  <td data-label={t('txt_org_organization')}>{invitation.organizationName}</td>
                  <td data-label={t('txt_org_invited_by')}>{invitation.invitedByEmail || t('txt_dash')}</td>
                  <td data-label={t('txt_status')}>
                    {invitation.status === ORG_STATUS.ACCEPTED ? t('txt_org_waiting_confirmation') : statusLabel(invitation.status)}
                  </td>
                  <td data-label={t('txt_actions')}>
                    <div className="actions">
                      {invitation.status === ORG_STATUS.INVITED && (
                        <button
                          type="button"
                          className="btn btn-primary"
                          disabled={busy}
                          onClick={() => void run(async () => {
                            await acceptInvitation(authedFetch, invitation);
                            await loadInvitations();
                          }, t('txt_org_invitation_accepted')).catch(() => undefined)}
                        >
                          <Check size={14} className="btn-icon" /> {t('txt_org_accept')}
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={busy}
                        onClick={() => void run(async () => {
                          await leaveOrganization(authedFetch, invitation.organizationId);
                          await loadInvitations();
                        }, t('txt_org_invitation_declined')).catch(() => undefined)}
                      >
                        <UserX size={14} className="btn-icon" /> {t('txt_org_decline')}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!!myFingerprint && (
            <p className="muted-inline org-fingerprint-note">
              <Fingerprint size={14} /> {t('txt_org_your_fingerprint')}: <strong>{myFingerprint}</strong>
            </p>
          )}
        </section>
      )}

      <section className="card">
        <div className="section-head">
          <h3>{t('nav_organizations')}</h3>
          <div className="actions">
            <button type="button" className="btn btn-secondary small" disabled={busy || loading} onClick={() => void (async () => {
              await props.onRefresh();
              await loadInvitations();
              if (selectedOrgId) await loadOrgData(selectedOrgId);
            })()}>
              <RefreshCw size={14} className="btn-icon" /> {t('txt_refresh')}
            </button>
            <button type="button" className="btn btn-primary small" disabled={busy} onClick={() => {
              setCreateName('');
              setCreateCollection(t('txt_org_default_collection'));
              setCreateOpen(true);
            }}>
              <Plus size={14} className="btn-icon" /> {t('txt_org_create')}
            </button>
          </div>
        </div>
        {organizations.length === 0 ? (
          <div className="empty empty-comfortable">{t('txt_org_none')}</div>
        ) : (
          <div className="org-switcher">
            {organizations.map((org) => (
              <button
                key={org.id}
                type="button"
                className={`org-switch-btn ${org.id === selectedOrgId ? 'active' : ''}`}
                onClick={() => {
                  setSelectedOrgId(org.id);
                  setTab('members');
                }}
              >
                <Building2 size={14} />
                <span>{org.name}</span>
                <small>{roleLabel(org.type)}</small>
              </button>
            ))}
          </div>
        )}
        {!!myFingerprint && invitations.length === 0 && (
          <p className="muted-inline org-fingerprint-note">
            <Fingerprint size={14} /> {t('txt_org_your_fingerprint')}: <strong>{myFingerprint}</strong>
          </p>
        )}
      </section>

      {selectedOrg && (
        <section className="card">
          <div className="org-tabs">
            {canAdmin && (
              <button type="button" className={`org-tab ${tab === 'members' ? 'active' : ''}`} onClick={() => setTab('members')}>
                <Users size={14} /> {t('txt_org_members')}
              </button>
            )}
            {canManageCollections && (
              <button type="button" className={`org-tab ${tab === 'collections' ? 'active' : ''}`} onClick={() => setTab('collections')}>
                <Layers size={14} /> {t('txt_org_collections')}
              </button>
            )}
            <button type="button" className={`org-tab ${tab === 'settings' || (!canAdmin && tab === 'members') ? 'active' : ''}`} onClick={() => setTab('settings')}>
              <Pencil size={14} /> {t('txt_settings')}
            </button>
          </div>

          {loading && <LoadingState lines={4} compact />}

          {!loading && canAdmin && tab === 'members' && (
            <>
              <div className="section-head">
                <h4>{t('txt_org_members')}</h4>
                <button type="button" className="btn btn-primary small" disabled={busy} onClick={() => openMemberDialog(null)}>
                  <UserPlus size={14} className="btn-icon" /> {t('txt_org_invite')}
                </button>
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('txt_email')}</th>
                    <th>{t('txt_org_role')}</th>
                    <th>{t('txt_status')}</th>
                    <th>{t('txt_actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((member) => {
                    const isSelf = member.userId === userId;
                    const ownerOnly = !isOwner && member.type !== ORG_TYPE.USER;
                    return (
                      <tr key={member.id}>
                        <td data-label={t('txt_email')}>
                          {member.email}
                          {member.name ? <div className="muted-inline">{member.name}</div> : null}
                        </td>
                        <td data-label={t('txt_org_role')}>{roleLabel(member.type)}</td>
                        <td data-label={t('txt_status')}>{statusLabel(member.status)}</td>
                        <td data-label={t('txt_actions')}>
                          <div className="actions">
                            {member.status === ORG_STATUS.ACCEPTED && !ownerOnly && (
                              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void startConfirm(member)}>
                                <UserCheck size={14} className="btn-icon" /> {t('txt_org_confirm')}
                              </button>
                            )}
                            {!isSelf && !ownerOnly && (
                              <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => openMemberDialog(member)}>
                                <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                              </button>
                            )}
                            {!isSelf && !ownerOnly && (
                              <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={busy}
                                onClick={() => void run(
                                  () => setMemberRevoked(authedFetch, selectedOrg.id, member.id, member.status !== ORG_STATUS.REVOKED),
                                  member.status === ORG_STATUS.REVOKED ? t('txt_org_member_restored') : t('txt_org_member_revoked')
                                ).catch(() => undefined)}
                              >
                                <UserX size={14} className="btn-icon" /> {member.status === ORG_STATUS.REVOKED ? t('txt_org_restore') : t('txt_org_revoke')}
                              </button>
                            )}
                            {!isSelf && !ownerOnly && (
                              <button type="button" className="btn btn-danger" disabled={busy} onClick={() => setRemoveTarget(member)}>
                                <UserMinus size={14} className="btn-icon" /> {t('txt_org_remove')}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}

          {!loading && canManageCollections && tab === 'collections' && (
            <>
              <div className="section-head">
                <h4>{t('txt_org_collections')}</h4>
                {(canAdmin || selectedOrg.permissions?.createNewCollections) && (
                  <button type="button" className="btn btn-primary small" disabled={busy} onClick={() => openCollectionDialog(null)}>
                    <Plus size={14} className="btn-icon" /> {t('txt_org_new_collection')}
                  </button>
                )}
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('txt_name')}</th>
                    <th>{t('txt_org_members')}</th>
                    <th>{t('txt_actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {collections.map((collection) => (
                    <tr key={collection.id}>
                      <td data-label={t('txt_name')}><Layers size={13} className="btn-icon" /> {collection.decName}</td>
                      <td data-label={t('txt_org_members')}>{collection.users.length}</td>
                      <td data-label={t('txt_actions')}>
                        {collection.manage && (
                          <div className="actions">
                            <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => openCollectionDialog(collection)}>
                              <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                            </button>
                            <button type="button" className="btn btn-danger" disabled={busy} onClick={() => setDeleteCollectionTarget(collection)}>
                              <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {!collections.length && (
                    <tr><td colSpan={3}><div className="empty">{t('txt_org_no_collections')}</div></td></tr>
                  )}
                </tbody>
              </table>
            </>
          )}

          {!loading && (tab === 'settings' || (!canAdmin && tab === 'members')) && (
            <div className="stack">
              {isOwner && (
                <div className="org-settings-row">
                  <label className="field">
                    <span>{t('txt_org_name')}</span>
                    <input className="input" value={orgName} onInput={(e) => setOrgName((e.currentTarget as HTMLInputElement).value)} />
                  </label>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={busy || !orgName.trim() || orgName.trim() === selectedOrg.name}
                    onClick={() => void run(
                      () => updateOrganization(authedFetch, selectedOrg.id, orgName.trim(), email),
                      t('txt_org_saved'),
                      { refreshVault: true }
                    ).catch(() => undefined)}
                  >
                    {t('txt_save')}
                  </button>
                </div>
              )}
              {!canAdmin && <p className="muted-inline">{t('txt_org_member_note')}</p>}
              <div className="actions">
                <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setLeaveOpen(true)}>
                  <LogOut size={14} className="btn-icon" /> {t('txt_org_leave')}
                </button>
                {isOwner && (
                  <button type="button" className="btn btn-danger" disabled={busy} onClick={() => {
                    setDeletePassword('');
                    setDeleteOrgOpen(true);
                  }}>
                    <Trash2 size={14} className="btn-icon" /> {t('txt_org_delete')}
                  </button>
                )}
              </div>
            </div>
          )}
        </section>
      )}

      <ConfirmDialog
        open={createOpen}
        title={t('txt_org_create')}
        message={t('txt_org_create_hint')}
        confirmText={t('txt_org_create')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy || !createName.trim() || !createCollection.trim()}
        onCancel={() => setCreateOpen(false)}
        onConfirm={() => void run(async () => {
          await createOrganization(authedFetch, {
            name: createName.trim(),
            billingEmail: email,
            collectionName: createCollection.trim(),
            userId,
          });
          setCreateOpen(false);
        }, t('txt_org_created'), { refreshVault: true }).catch(() => undefined)}
      >
        <label className="field">
          <span>{t('txt_org_name')}</span>
          <input className="input" value={createName} onInput={(e) => setCreateName((e.currentTarget as HTMLInputElement).value)} />
        </label>
        <label className="field">
          <span>{t('txt_org_first_collection')}</span>
          <input className="input" value={createCollection} onInput={(e) => setCreateCollection((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={inviteOpen || !!memberDialog}
        title={memberDialog ? t('txt_org_edit_member', { email: memberDialog.email }) : t('txt_org_invite')}
        message={memberDialog ? undefined : t('txt_org_invite_hint')}
        confirmText={memberDialog ? t('txt_save') : t('txt_org_invite')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy || (!memberDialog && !inviteEmails.trim())}
        onCancel={() => {
          setInviteOpen(false);
          setMemberDialog(null);
        }}
        onConfirm={() => {
          if (!selectedOrg) return;
          const access = isAdminType(memberType) ? [] : accessListFrom(memberAccess);
          if (memberDialog) {
            void run(async () => {
              await editMember(authedFetch, selectedOrg.id, memberDialog.id, memberType, access);
              setMemberDialog(null);
            }, t('txt_org_member_saved')).catch(() => undefined);
            return;
          }
          const emails = inviteEmails.split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean);
          void run(async () => {
            await inviteMembers(authedFetch, selectedOrg.id, emails, memberType, access);
            setInviteOpen(false);
          }, t('txt_org_invited')).catch(() => undefined);
        }}
      >
        {!memberDialog && (
          <label className="field">
            <span>{t('txt_org_invite_emails')}</span>
            <input className="input" placeholder="name@example.com" value={inviteEmails} onInput={(e) => setInviteEmails((e.currentTarget as HTMLInputElement).value)} />
          </label>
        )}
        <label className="field">
          <span>{t('txt_org_role')}</span>
          <select className="input" value={memberType} onInput={(e) => setMemberType(Number((e.currentTarget as HTMLSelectElement).value))}>
            {Array.from(new Set([...roleOptions, memberDialog?.type ?? ORG_TYPE.USER])).map((type) => (
              <option key={type} value={type}>{roleLabel(type)}</option>
            ))}
          </select>
        </label>
        {isAdminType(memberType) ? (
          <p className="muted-inline">{t('txt_org_admin_access_all')}</p>
        ) : (
          <div className="field">
            <span>{t('txt_org_collection_access')}</span>
            <AccessMatrix
              rows={collectionRows}
              values={memberAccess}
              onChange={(id, level) => setMemberAccess((prev) => ({ ...prev, [id]: level }))}
              emptyText={t('txt_org_no_collections')}
            />
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={!!confirmTarget}
        title={t('txt_org_confirm_member', { email: confirmTarget?.member.email || '' })}
        message={t('txt_org_confirm_fingerprint_hint')}
        confirmText={t('txt_org_confirm')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy}
        onCancel={() => setConfirmTarget(null)}
        onConfirm={() => {
          if (!selectedOrg || !confirmTarget) return;
          void run(async () => {
            await confirmMember(authedFetch, selectedOrg.id, confirmTarget.member.id, confirmTarget.publicKey, orgKeys);
            setConfirmTarget(null);
          }, t('txt_org_member_confirmed')).catch(() => undefined);
        }}
      >
        <div className="org-fingerprint-box"><Fingerprint size={16} /> <strong>{confirmTarget?.phrase}</strong></div>
      </ConfirmDialog>

      <ConfirmDialog
        open={!!removeTarget}
        title={t('txt_org_remove')}
        message={t('txt_org_remove_confirm', { email: removeTarget?.email || '' })}
        danger
        confirmText={t('txt_org_remove')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy}
        onCancel={() => setRemoveTarget(null)}
        onConfirm={() => {
          if (!selectedOrg || !removeTarget) return;
          void run(async () => {
            await removeMember(authedFetch, selectedOrg.id, removeTarget.id);
            setRemoveTarget(null);
          }, t('txt_org_member_removed')).catch(() => undefined);
        }}
      />

      <ConfirmDialog
        open={!!collectionDialog}
        title={collectionDialog?.id ? t('txt_org_edit_collection') : t('txt_org_new_collection')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy || !collectionName.trim()}
        onCancel={() => setCollectionDialog(null)}
        onConfirm={() => {
          if (!selectedOrg || !collectionDialog) return;
          void run(async () => {
            await saveCollection(authedFetch, selectedOrg.id, orgKeys, {
              id: collectionDialog.id,
              name: collectionName.trim(),
              users: accessListFrom(collectionAccess),
            });
            setCollectionDialog(null);
          }, t('txt_org_collection_saved'), { refreshVault: true }).catch(() => undefined);
        }}
      >
        <label className="field">
          <span>{t('txt_name')}</span>
          <input className="input" value={collectionName} onInput={(e) => setCollectionName((e.currentTarget as HTMLInputElement).value)} />
        </label>
        {canAdmin && (
          <div className="field">
            <span>{t('txt_org_member_access')}</span>
            <AccessMatrix
              rows={memberRows}
              values={collectionAccess}
              onChange={(id, level) => setCollectionAccess((prev) => ({ ...prev, [id]: level }))}
              emptyText={t('txt_org_no_limited_members')}
            />
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={!!deleteCollectionTarget}
        title={t('txt_org_delete_collection')}
        message={t('txt_org_delete_collection_confirm', { name: deleteCollectionTarget?.decName || '' })}
        danger
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy}
        onCancel={() => setDeleteCollectionTarget(null)}
        onConfirm={() => {
          if (!selectedOrg || !deleteCollectionTarget) return;
          void run(async () => {
            await deleteCollection(authedFetch, selectedOrg.id, deleteCollectionTarget.id);
            setDeleteCollectionTarget(null);
          }, t('txt_org_collection_deleted'), { refreshVault: true }).catch(() => undefined);
        }}
      />

      <ConfirmDialog
        open={leaveOpen}
        title={t('txt_org_leave')}
        message={t('txt_org_leave_confirm', { name: selectedOrg?.name || '' })}
        danger
        confirmText={t('txt_org_leave')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy}
        onCancel={() => setLeaveOpen(false)}
        onConfirm={() => {
          if (!selectedOrg) return;
          void run(async () => {
            await leaveOrganization(authedFetch, selectedOrg.id);
            forgetOrganization(selectedOrg.id);
            setLeaveOpen(false);
            setSelectedOrgId('');
          }, t('txt_org_left'), { refreshVault: true }).catch(() => undefined);
        }}
      />

      <ConfirmDialog
        open={deleteOrgOpen}
        title={t('txt_org_delete')}
        message={t('txt_org_delete_confirm', { name: selectedOrg?.name || '' })}
        danger
        confirmText={t('txt_org_delete')}
        cancelText={t('txt_cancel')}
        confirmDisabled={busy || !deletePassword}
        onCancel={() => setDeleteOrgOpen(false)}
        onConfirm={() => {
          if (!selectedOrg) return;
          void run(async () => {
            const derived = await deriveLoginHash(email, deletePassword, props.defaultKdfIterations);
            await deleteOrganization(authedFetch, selectedOrg.id, derived.hash);
            forgetOrganization(selectedOrg.id);
            setDeleteOrgOpen(false);
            setDeletePassword('');
            setSelectedOrgId('');
          }, t('txt_org_deleted'), { refreshVault: true }).catch(() => undefined);
        }}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" autoComplete="current-password" value={deletePassword} onInput={(e) => setDeletePassword((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>
    </div>
  );
}
