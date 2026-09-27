/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Monochrome accent. "Brand" is now white/grey - on a black ground the
        // accent is contrast and weight, not hue (Apple: hierarchy from
        // weight + size + material, colour reserved for meaning).
        brand: {
          50: "#ffffff",
          100: "#fafafa",
          300: "#a3a3a3",
          400: "#d4d4d4",
          500: "#e5e5e5",
          600: "#ffffff",
          700: "#e5e5e5",
        },
        // Surface ramp on true black. 950 is the ground (#000); the rest are
        // near-black raised materials, meant to be used translucent (…/70) so
        // they read as layers of the same black rather than new colours.
        ink: {
          950: "#000000",
          900: "#0a0a0a",
          850: "#101010",
          800: "#1a1a1a",
          700: "#262626",
          600: "#333333",
        },
        // Neutral grey text ramp - replaces Tailwind's blue-tinted slate so no
        // stray colour survives in the monochrome scheme.
        slate: {
          100: "#f5f5f5",
          200: "#e5e5e5",
          300: "#d4d4d4",
          400: "#a3a3a3",
          500: "#737373",
          600: "#525252",
          700: "#404040",
          800: "#262626",
          900: "#171717",
          950: "#0a0a0a",
        },
      },
      fontFamily: {
        // Menlo everywhere - the app is a single monospaced voice. Both the
        // default (sans) and explicit `font-mono` resolve to it.
        sans: ["Menlo", "ui-monospace", "SFMono-Regular", "Monaco", "monospace"],
        mono: ["Menlo", "ui-monospace", "SFMono-Regular", "Monaco", "monospace"],
      },
      keyframes: {
        "fade-in": { from: { opacity: "0", transform: "translateY(3px)" }, to: { opacity: "1", transform: "none" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        // Short, non-vestibular entrance - dropped entirely under reduced motion.
        "fade-in": "fade-in 0.22s cubic-bezier(0.2, 0, 0, 1)",
      },
    },
  },
  plugins: [],
};
