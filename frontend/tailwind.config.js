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
        canvas: '#0a0f1d',
        panel: '#0f172a',
        elevated: '#1e293b',
        subtle: '#141e33',
        brand: {
          cyan: '#06b6d4',
          blue: '#3b82f6',
        },
        severity: {
          info: '#38bdf8',
          low: '#818cf8',
          medium: '#fbbf24',
          high: '#fb923c',
          critical: '#f87171',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
