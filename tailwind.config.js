/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./*.html",
    "./js/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ice: '#E4DDD3',
        mint: {
          DEFAULT: '#00A19B',
          dark: '#008680',
          light: 'rgba(0, 161, 155, 0.15)',
        },
        primary: '#1A1A1A',
        secondary: '#666666',
        tertiary: '#999999',
        card: 'rgba(255, 255, 255, 0.7)',
      },
      fontFamily: {
        heading: ['Poppins', 'Inter', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        logo: ['"Playfair Display"', 'serif'],
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}
