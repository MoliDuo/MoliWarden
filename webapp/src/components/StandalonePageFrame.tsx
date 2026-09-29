import type { ComponentChildren } from 'preact';
import { APP_VERSION } from '@shared/app-version';
import { BrandLockup } from '@/components/BrandMark';

const REPOSITORY_URL = 'https://github.com/moliduo/MoliWarden';

interface StandalonePageFrameProps {
  title: string;
  eyebrow?: ComponentChildren;
  titleAccessory?: ComponentChildren;
  children: ComponentChildren;
}

export default function StandalonePageFrame(props: StandalonePageFrameProps) {
  return (
    <div className="standalone-shell">
      <div className="standalone-brand">
        <BrandLockup size={22} />
      </div>

      <div className="auth-card">
        {props.eyebrow && <div className="standalone-eyebrow">{props.eyebrow}</div>}
        <div className="standalone-title-row">
          <h1 className="standalone-title">{props.title}</h1>
          {props.titleAccessory}
        </div>
        {props.children}
      </div>

      <div className="standalone-footer">
        <a href={REPOSITORY_URL} target="_blank" rel="noreferrer">
          MoliWarden
        </a>
        <span aria-hidden="true">·</span>
        <a href={`${REPOSITORY_URL}/releases`} target="_blank" rel="noreferrer" className="standalone-version">
          v{APP_VERSION}
        </a>
      </div>
    </div>
  );
}
