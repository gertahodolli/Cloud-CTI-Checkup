/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Background colors (semantic)
        background: {
          base: '#0E1117',
          elevated: '#121826',
          surface: '#0B0F14',
          hover: '#1a2233',
        },
        // Border colors
        border: {
          DEFAULT: '#1E293B',
          hover: '#334155',
          focus: 'rgba(245, 158, 11, 0.5)',
        },
        // Text colors (semantic)
        foreground: {
          DEFAULT: '#F8FAFC',
          muted: '#94A3B8',
          disabled: '#64748B',
        },
        // Accent colors
        accent: {
          DEFAULT: '#F59E0B',
          hover: '#D97706',
          muted: 'rgba(245, 158, 11, 0.1)',
        },
        // Severity colors (for charts and badges)
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#3B82F6',
          info: '#64748B',
        },
        // Status colors
        success: '#22C55E',
        warning: '#EAB308',
        error: '#EF4444',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'glow-amber': '0 0 20px rgba(245, 158, 11, 0.1)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.1)',
      },
    },
  },
  plugins: [],
}
