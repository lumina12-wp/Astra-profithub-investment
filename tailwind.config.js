// tailwind.config.js
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#1a237e',
        accent: '#00c853',
        background: '#0a0a0a',
        dark: '#121212',
        gold: '#ffd700'
      },
    },
  },
  plugins: [],
}