import { useMemo, useState } from 'preact/hooks';
import { AlertTriangle, Copy, RefreshCw } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';
import type { SecretWarning } from '@/lib/types';

const VERCEL_DASHBOARD_URL = 'https://vercel.com/dashboard';

// Shown instead of the vault while JWT_SECRET or ENCRYPTION_KEY is missing
// or too short, with the steps to set it.
export default function SecretWarningPage(props: SecretWarning) {
  const [seed, setSeed] = useState(0);
  const [copyHint, setCopyHint] = useState('');

  const generatedSecret = useMemo(() => generateSecret(Math.max(32, props.minLength)), [seed, props.minLength]);

  const name = props.name;
  const isMissing = props.reason === 'missing';
  const title = isMissing ? t('txt_secret_title_missing', { name }) : t('txt_secret_title_too_short', { name });
  const fixTitle = isMissing ? t('txt_secret_how_to_fix_add', { name }) : t('txt_secret_how_to_fix_replace', { name });
  const fixStep1 = isMissing ? t('txt_secret_add_step_1') : t('txt_secret_replace_step_1', { min: props.minLength });
  const fixStep2Prefix = isMissing ? t('txt_secret_add_step_2_prefix') : t('txt_secret_replace_step_2_prefix');
  const fixStep2Suffix = isMissing ? t('txt_secret_add_step_2_suffix', { name }) : t('txt_secret_replace_step_2_suffix', { name });
  const fixStep3 = isMissing ? t('txt_secret_add_step_3') : t('txt_secret_replace_step_3');
  const about = name === 'JWT_SECRET' ? t('txt_secret_jwt_body') : t('txt_secret_encryption_key_body');

  return (
    <div className="auth-page">
      <StandalonePageFrame title={title}>
        <div className="jwt-warning-head">
          <AlertTriangle size={20} />
          <strong>{t('txt_secret_warning_subtitle')}</strong>
        </div>

        <div className="jwt-warning-box">
          <div className="jwt-warning-label">{t('txt_secret_what_is', { name })}</div>
          <p className="jwt-warning-copy">{about}</p>

          <div className="jwt-warning-label">{fixTitle}</div>
          <ol className="jwt-warning-list">
            <li>{fixStep1}</li>
            <li>
              {fixStep2Prefix}
              <a href={VERCEL_DASHBOARD_URL} className="jwt-inline-link" target="_blank" rel="noreferrer">
                {t('txt_settings')}
              </a>
              {fixStep2Suffix}
              <div className="jwt-secret-fields">
                <div className="jwt-secret-row">
                  <span>{t('txt_secret_type_label')}</span>
                  <strong>{t('txt_secret_type_value')}</strong>
                </div>
                <div className="jwt-secret-row">
                  <span>{t('txt_secret_name_label')}</span>
                  <strong>{name}</strong>
                </div>
                <div className="jwt-secret-row">
                  <span>{t('txt_secret_value_label')}</span>
                  <strong>{t('txt_secret_value_requirement', { min: props.minLength })}</strong>
                </div>
              </div>
            </li>
            <li>{fixStep3}</li>
          </ol>

          <div className="jwt-generator">
            <div className="jwt-warning-label">{t('txt_random_secret_generator')}</div>
            <input className="input input-readonly" readOnly value={generatedSecret} />
            <div className="jwt-generator-actions">
              <button type="button" className="btn btn-primary" onClick={() => setSeed((v) => v + 1)}>
                <RefreshCw size={15} className="btn-icon" />
                {t('txt_regenerate')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={async () => {
                  await copyTextToClipboard(generatedSecret, {
                    onSuccess: () => setCopyHint(t('txt_copied')),
                    onError: () => setCopyHint(t('txt_copy_failed')),
                  });
                  window.setTimeout(() => setCopyHint(''), 1500);
                }}
              >
                <Copy size={15} className="btn-icon" />
                {t('txt_copy')}
              </button>
              {copyHint && <span className="jwt-copy-hint">{copyHint}</span>}
            </div>
          </div>
        </div>
      </StandalonePageFrame>
    </div>
  );
}

function generateSecret(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  const maxUnbiasedByte = Math.floor(256 / chars.length) * chars.length;
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const value of bytes) {
      if (value >= maxUnbiasedByte) continue;
      out += chars[value % chars.length];
      if (out.length >= length) break;
    }
  }
  return out;
}
