/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Accent — indigo
        accent: {
          DEFAULT: '#4f46e5',
          hover:   '#4338ca',
          soft:    '#eef2ff',
          text:    '#3730a3',
          border:  '#c7d2fe',
        },
        // Surfaces
        surface: {
          base:    '#f1f5f9',
          card:    '#ffffff',
          subtle:  '#fafbfc',
          hover:   '#f1f5f9',
        },
        // Text
        ink: {
          DEFAULT:   '#0f172a',
          secondary: '#64748b',
          muted:     '#94a3b8',
        },
        // Severity
        critical: { DEFAULT: '#dc2626', bg: '#fef2f2', bd: '#fecaca' },
        high:     { DEFAULT: '#ea580c', bg: '#fff7ed', bd: '#fed7aa' },
        medium:   { DEFAULT: '#ca8a04', bg: '#fefce8', bd: '#fde68a' },
        low:      { DEFAULT: '#2563eb', bg: '#eff6ff', bd: '#bfdbfe' },
        // Framework
        maestro:  { DEFAULT: '#7c3aed', bg: '#f5f3ff' },
        atfaa:    { DEFAULT: '#0891b2', bg: '#ecfeff' },
        // Success
        success:  { DEFAULT: '#16a34a', bg: '#f0fdf4', bd: '#bbf7d0' },
      },
      fontFamily: {
        sans: ['var(--font-outfit)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        sm:  '6px',
        md:  '10px',
        lg:  '14px',
        xl:  '16px',
        '2xl': '20px',
      },
      animation: {
        'fade-up':   'fadeUp 0.4s ease',
        'spin-md':   'spin 0.8s linear infinite',
        'barpulse':  'barpulse 1.2s ease-in-out infinite',
        'shimmer':   'shimmer 1.5s infinite',
      },
      keyframes: {
        fadeUp: {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to:   { opacity: '1', transform: 'none' },
        },
        barpulse: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.5' },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition:  '200% 0' },
        },
      },
      boxShadow: {
        card:    '0 1px 3px rgba(15,23,42,0.04)',
        'card-md':'0 4px 12px rgba(15,23,42,0.08)',
      },
    },
  },
  plugins: [],
}
