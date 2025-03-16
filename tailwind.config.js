/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/*"],
  theme: {
    extend: {
      colors: {
        background: '#121212',
        surface: '#1e1e1e',
        primary: '#b488f5',
        secondary: '#63d7c6',
        onbackground: '#dadada',
        onsurface: '#e1e1e1',
        onprimary: '#020202',
        onsecondary: '#000000',
        navbar: '#232323',
        onprimaryhover: '#cbacfa',
      },
    },
  },
  plugins: [],
}


