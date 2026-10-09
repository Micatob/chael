/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#050810',
          surface: '#0d1117',
          panel: '#0f1923',
          border: '#1e3a5f',
          muted: '#4a7c99',
          text: '#c8e6f0',
          accent: '#00d4ff',
          accent2: '#7b2ff7',
          green: '#00ff88',
          critical: '#ff2d55',
          high: '#ff9500',
          medium: '#ffcc00',
          low: '#30d158',
        },
        severity: {
          CRITICAL: '#ff2d55',
          HIGH: '#ff9500',
          MEDIUM: '#ffcc00',
          LOW: '#30d158',
          INFO: '#4a7c99',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'cyber-grid': 'linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)',
        'cyber-glow': 'radial-gradient(ellipse at top, rgba(0,212,255,0.15) 0%, transparent 60%)',
      },
      backgroundSize: {
        'cyber-grid': '40px 40px',
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0,212,255,0.15), 0 0 40px rgba(0,212,255,0.05)',
        'cyber-sm': '0 0 8px rgba(0,212,255,0.2)',
        'cyber-critical': '0 0 20px rgba(255,45,85,0.2)',
        'cyber-green': '0 0 20px rgba(0,255,136,0.2)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.2s ease-out',
        'scan-line': 'scanLine 3s linear infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scanLine: {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};