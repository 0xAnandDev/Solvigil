# Solvigil Landing Page

This is the front-end landing page for Solvigil, a smart contract security scanning tool that detects vulnerabilities in Solidity contracts.

## Features
- **Modern, Responsive Design**: Built with Tailwind CSS and custom animations.
- **Vite & PostCSS**: Fast development server and optimized build process.
- **Custom Theming**: Styled with specific Ice Latte (`#E4DDD3`) and Mint (`#00A19B`) colors.
- **Glassmorphism UI**: Beautiful semi-transparent frosted cards.
- **Smooth Animations**: Scroll-based intersection observer reveals.

## Project Structure
```
solvigil/
├── index.html            # Main HTML structure
├── package.json          # Node dependencies and scripts
├── tailwind.config.js    # Tailwind configuration with custom colors/fonts
├── postcss.config.js     # PostCSS configuration for Tailwind
├── css/
│   ├── tailwind.css      # Tailwind base imports
│   └── styles.css        # Custom animations and additional styles
├── js/
│   ├── main.js           # Main entry point and scroll animations
│   └── interactions.js   # Button interactions and smooth scrolling
└── assets/
    ├── images/           # Image assets
    ├── icons/            # Icon assets
    └── fonts/            # Local fonts (if not using Google Fonts)
```

## Getting Started

### Prerequisites
- Node.js (v16+)
- npm or yarn

### Installation
1. Clone the repository or navigate to the project root.
2. Install dependencies:
   ```bash
   npm install
   ```

### Development Server
Run the local Vite development server:
```bash
npm run dev
```
Open `http://localhost:5173` in your browser.

### Build for Production
To create an optimized production build:
```bash
npm run build
```
The output will be in the `dist/` directory.

### Preview Production Build
```bash
npm run preview
```

## Styling Details
- **Fonts**: `Outfit` (headings) and `Inter` (body).
- **Background Animations**: Custom infinite wave animation in `css/styles.css`.
- **Scroll Effects**: Managed using the Intersection Observer API in `js/main.js`.
