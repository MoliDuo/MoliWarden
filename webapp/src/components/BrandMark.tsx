import { BRAND_MARK } from '@shared/brand-mark';

interface BrandMarkProps {
  size?: number;
  className?: string;
}

export function BrandMark(props: BrandMarkProps) {
  const size = props.size ?? 20;
  const { bow, bit, transform, strokeWidth, viewBox } = BRAND_MARK;
  return (
    <svg className={props.className} width={size} height={size} viewBox={viewBox} aria-hidden="true" focusable="false">
      <g transform={transform} fill="none" stroke="currentColor" stroke-width={strokeWidth} stroke-linecap="round" stroke-linejoin="round">
        <circle cx={bow.cx} cy={bow.cy} r={bow.r} />
        <path d={bit} />
      </g>
    </svg>
  );
}

// Key mark plus the product name, as shown in the top bar and on standalone pages.
export function BrandLockup(props: { className?: string; size?: number }) {
  return (
    <span className={`brand-lockup${props.className ? ` ${props.className}` : ''}`}>
      <BrandMark size={props.size} className="brand-lockup-mark" />
      <span className="brand-lockup-name">MoliWarden</span>
    </span>
  );
}
