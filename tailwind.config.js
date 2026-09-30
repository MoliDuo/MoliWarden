/** @type {import('tailwindcss').Config} */
export default {
  content: ['./webapp/index.html', './webapp/src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        canvas: 'var(--bg)',
        panel: 'var(--panel)',
        'panel-soft': 'var(--panel-soft)',
        'panel-muted': 'var(--panel-muted)',
        line: 'var(--line)',
        'line-soft': 'var(--line-soft)',
        ink: 'var(--text)',
        muted: 'var(--muted)',
        'muted-strong': 'var(--muted-strong)',
        faint: 'var(--faint)',
        'line-strong': 'var(--line-strong)',
        brand: 'var(--primary)',
        'brand-fg': 'var(--primary-fg)',
        danger: 'var(--danger)',
        'danger-soft': 'var(--danger-soft)',
      },
      borderRadius: {
        DEFAULT: 'var(--radius-sm)',
        sm: 'var(--radius-sm)',
        md: 'var(--radius-md)',
        lg: 'var(--radius-lg)',
        xl: 'var(--radius-xl)',
        '2xl': 'var(--radius-2xl)',
      },
      boxShadow: {
        soft: 'var(--shadow-sm)',
        panel: 'var(--shadow-md)',
        elevated: 'var(--shadow-lg)',
      },
      fontFamily: {
        sans: 'var(--font-sans)',
        mono: 'var(--font-mono)',
      },
    },
  },
  plugins: [],
};
