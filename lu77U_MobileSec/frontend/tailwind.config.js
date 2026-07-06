/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Brand accent — a cyan/teal that reads as "security tooling".
        brand: {
          50: "#ecfeff",
          100: "#cffafe",
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
          600: "#0891b2",
          700: "#0e7490",
        },
        // Neutral surface ramp (slate-ish, slightly deeper for OLED comfort).
        ink: {
          950: "#0a0f1a",
          900: "#0f172a",
          850: "#141d31",
          800: "#1e293b",
          700: "#334155",
          600: "#475569",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      keyframes: {
        "fade-in": { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "none" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "fade-in": "fade-in 0.25s ease-out",
      },
    },
  },
  plugins: [],
};