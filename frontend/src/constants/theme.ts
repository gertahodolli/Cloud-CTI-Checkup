// ============================================================
// Theme Configuration - Design Tokens
// Single source of truth for all colors and styling
// ============================================================

// ============================================================
// Color Palette (CSS Variable Names)
// ============================================================

export const COLORS = {
  // Background colors
  background: {
    base: '#0E1117',      // Main app background
    elevated: '#121826',   // Cards, panels
    surface: '#0B0F14',    // Sidebar, modals
    hover: '#1a2233',      // Hover states
  },

  // Border colors
  border: {
    default: '#1E293B',
    hover: '#334155',
    focus: 'rgba(245, 158, 11, 0.5)', // amber-500/50
  },

  // Text colors
  text: {
    primary: '#F8FAFC',    // slate-50
    secondary: '#E2E8F0',  // slate-200
    muted: '#94A3B8',      // slate-400
    disabled: '#64748B',   // slate-500
  },

  // Accent colors
  accent: {
    primary: '#F59E0B',    // amber-500
    hover: '#D97706',      // amber-600
    muted: 'rgba(245, 158, 11, 0.1)',
  },

  // Severity colors
  severity: {
    critical: {
      text: '#F87171',     // red-400
      bg: 'rgba(239, 68, 68, 0.1)',
      border: 'rgba(239, 68, 68, 0.3)',
    },
    high: {
      text: '#FB923C',     // orange-400
      bg: 'rgba(249, 115, 22, 0.1)',
      border: 'rgba(249, 115, 22, 0.3)',
    },
    medium: {
      text: '#FACC15',     // yellow-400
      bg: 'rgba(234, 179, 8, 0.1)',
      border: 'rgba(234, 179, 8, 0.3)',
    },
    low: {
      text: '#60A5FA',     // blue-400
      bg: 'rgba(59, 130, 246, 0.1)',
      border: 'rgba(59, 130, 246, 0.3)',
    },
    info: {
      text: '#94A3B8',     // slate-400
      bg: 'rgba(100, 116, 139, 0.1)',
      border: 'rgba(100, 116, 139, 0.3)',
    },
  },

  // Status colors
  status: {
    success: {
      text: '#4ADE80',     // green-400
      bg: 'rgba(34, 197, 94, 0.1)',
    },
    warning: {
      text: '#FACC15',     // yellow-400
      bg: 'rgba(234, 179, 8, 0.1)',
    },
    error: {
      text: '#F87171',     // red-400
      bg: 'rgba(239, 68, 68, 0.1)',
    },
  },

  // Finding status colors
  findingStatus: {
    open: {
      text: '#F87171',     // red-400
      bg: 'rgba(239, 68, 68, 0.1)',
    },
    resolved: {
      text: '#4ADE80',     // green-400
      bg: 'rgba(34, 197, 94, 0.1)',
    },
    suppressed: {
      text: '#94A3B8',     // slate-400
      bg: 'rgba(100, 116, 139, 0.1)',
    },
  },
} as const;

// ============================================================
// Tailwind Class Mappings (for components)
// ============================================================

export const TW_COLORS = {
  // Backgrounds
  bgBase: 'bg-[#0E1117]',
  bgElevated: 'bg-[#121826]',
  bgSurface: 'bg-[#0B0F14]',
  bgHover: 'hover:bg-[#1a2233]',

  // Borders
  borderDefault: 'border-[#1E293B]',
  borderHover: 'hover:border-[#334155]',

  // Text
  textPrimary: 'text-slate-100',
  textSecondary: 'text-slate-200',
  textMuted: 'text-slate-400',
  textDisabled: 'text-slate-500',

  // Accent
  textAccent: 'text-amber-400',
  bgAccent: 'bg-amber-500/10',
  borderAccent: 'border-amber-500/50',
} as const;

// ============================================================
// Severity Tailwind Classes
// ============================================================

export const SEVERITY_STYLES = {
  critical: {
    text: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
  },
  high: {
    text: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
  },
  medium: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
  },
  low: {
    text: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
  },
  info: {
    text: 'text-slate-400',
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/30',
  },
} as const;

// ============================================================
// Status Tailwind Classes
// ============================================================

export const STATUS_STYLES = {
  open: {
    text: 'text-red-400',
    bg: 'bg-red-500/10',
  },
  resolved: {
    text: 'text-green-400',
    bg: 'bg-green-500/10',
  },
  suppressed: {
    text: 'text-slate-400',
    bg: 'bg-slate-500/10',
  },
} as const;

// ============================================================
// Chart Colors (for Recharts)
// ============================================================

export const CHART_COLORS = {
  critical: '#EF4444',  // red-500
  high: '#F97316',      // orange-500
  medium: '#EAB308',    // yellow-500
  low: '#3B82F6',       // blue-500
  info: '#64748B',      // slate-500
  accent: '#F59E0B',    // amber-500
  success: '#22C55E',   // green-500
  grid: '#1E293B',
  text: '#94A3B8',
} as const;
