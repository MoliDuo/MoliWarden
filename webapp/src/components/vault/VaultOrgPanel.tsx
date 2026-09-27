import { useMemo, useState } from 'preact/hooks';
import { Layers, Share2 } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import { t } from '@/lib/i18n';
import type { Cipher, ProfileOrganization, VaultCollection } from '@/lib/types';

// Organization section of the item detail view: where the item lives, and
// the actions to move a personal item into an organization or change the
// collections of an organization item.

interface VaultOrgPanelProps {
  cipher: Cipher;
  organizations: ProfileOrganization[];
  collections: VaultCollection[];
  busy: boolean;
  onShare: (cipher: Cipher, organizationId: string, collectionIds: string[]) => Promise<void>;
  onUpdateCollections: (cipher: Cipher, collectionIds: string[]) => Promise<void>;
}

function collectionLabel(collection: VaultCollection): string {
  return collection.decName || t('txt_org_collection_unnamed');
}

function CollectionChecklist(props: {
  collections: VaultCollection[];
  selected: Record<string, boolean>;
  onToggle: (id: string, checked: boolean) => void;
}) {
  if (!props.collections.length) {
    return <p className="muted-inline">{t('txt_org_no_writable_collections')}</p>;
  }
  return (
    <div className="org-collection-checklist">
      {props.collections.map((collection) => (
        <label key={collection.id} className="check-line check-line-compact">
          <input
            type="checkbox"
            checked={!!props.selected[collection.id]}
            disabled={!!collection.readOnly}
            onChange={(e) => props.onToggle(collection.id, (e.currentTarget as HTMLInputElement).checked)}
          />
          <span>{collectionLabel(collection)}</span>
        </label>
      ))}
    </div>
  );
}

export default function VaultOrgPanel(props: VaultOrgPanelProps) {
  const [shareOpen, setShareOpen] = useState(false);
  const [collectionsOpen, setCollectionsOpen] = useState(false);
  const [targetOrgId, setTargetOrgId] = useState('');
  const [selected, setSelected] = useState<Record<string, boolean>>({});

  const orgId = props.cipher.organizationId || null;
  const org = orgId ? props.organizations.find((item) => item.id === orgId) : null;
  const itemCollections = useMemo(
    () => props.collections.filter((collection) => (props.cipher.collectionIds || []).includes(collection.id)),
    [props.collections, props.cipher.collectionIds]
  );
  const collectionsOf = (id: string) => props.collections.filter((collection) => collection.organizationId === id);
  const writableCollectionsOf = (id: string) => collectionsOf(id).filter((collection) => !collection.readOnly);
  const selectedIds = Object.keys(selected).filter((id) => selected[id]);
  const toggle = (id: string, checked: boolean) => setSelected((prev) => ({ ...prev, [id]: checked }));

  if (!orgId && !props.organizations.length) return null;
  const isDeleted = !!props.cipher.deletedDate;

  return (
    <div className="card org-panel">
      <h4>{t('txt_org_ownership')}</h4>
      {orgId ? (
        <>
          <div className="kv-row">
            <span className="kv-label">{t('txt_org_organization')}</span>
            <div className="kv-main">
              <strong>{org?.name || t('txt_org_unknown')}</strong>
            </div>
          </div>
          <div className="kv-row">
            <span className="kv-label">{t('txt_org_collections')}</span>
            <div className="kv-main org-chip-row">
              {itemCollections.length
                ? itemCollections.map((collection) => (
                    <span key={collection.id} className="org-chip"><Layers size={12} /> {collectionLabel(collection)}</span>
                  ))
                : <span className="muted-inline">-</span>}
            </div>
            {props.cipher.edit !== false && !isDeleted && (
              <div className="kv-actions">
                <button
                  type="button"
                  className="btn btn-secondary small"
                  disabled={props.busy}
                  onClick={() => {
                    setSelected(Object.fromEntries((props.cipher.collectionIds || []).map((id) => [id, true])));
                    setCollectionsOpen(true);
                  }}
                >
                  {t('txt_edit')}
                </button>
              </div>
            )}
          </div>
          {props.cipher.edit === false && <p className="muted-inline">{t('txt_org_item_read_only')}</p>}
        </>
      ) : (
        <div className="kv-row">
          <span className="kv-label">{t('txt_org_owner')}</span>
          <div className="kv-main"><strong>{t('txt_org_my_vault')}</strong></div>
          {!isDeleted && (
            <div className="kv-actions">
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={props.busy}
                onClick={() => {
                  setTargetOrgId(props.organizations[0]?.id || '');
                  setSelected({});
                  setShareOpen(true);
                }}
              >
                <Share2 size={14} className="btn-icon" /> {t('txt_org_move_to_organization')}
              </button>
            </div>
          )}
        </div>
      )}

      <ConfirmDialog
        open={shareOpen}
        title={t('txt_org_move_to_organization')}
        message={t('txt_org_move_warning')}
        variant="warning"
        confirmText={t('txt_org_move')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy || !targetOrgId || !selectedIds.length}
        onCancel={() => setShareOpen(false)}
        onConfirm={() => {
          void props.onShare(props.cipher, targetOrgId, selectedIds).then(() => setShareOpen(false)).catch(() => undefined);
        }}
      >
        <label className="field">
          <span>{t('txt_org_organization')}</span>
          <select
            className="input"
            value={targetOrgId}
            onInput={(e) => {
              setTargetOrgId((e.currentTarget as HTMLSelectElement).value);
              setSelected({});
            }}
          >
            {props.organizations.map((item) => (
              <option key={item.id} value={item.id}>{item.name}</option>
            ))}
          </select>
        </label>
        <div className="field">
          <span>{t('txt_org_collections')}</span>
          <CollectionChecklist collections={writableCollectionsOf(targetOrgId)} selected={selected} onToggle={toggle} />
        </div>
      </ConfirmDialog>

      <ConfirmDialog
        open={collectionsOpen}
        title={t('txt_org_edit_collections')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        confirmDisabled={props.busy || !selectedIds.length}
        onCancel={() => setCollectionsOpen(false)}
        onConfirm={() => {
          void props.onUpdateCollections(props.cipher, selectedIds).then(() => setCollectionsOpen(false)).catch(() => undefined);
        }}
      >
        <CollectionChecklist collections={orgId ? collectionsOf(orgId) : []} selected={selected} onToggle={toggle} />
      </ConfirmDialog>
    </div>
  );
}
