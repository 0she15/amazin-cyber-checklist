import "./globals.css"
export const metadata = {
  title: "Amazin Cyber — M365 Security Checklist",
  description: "Microsoft 365 security assessment checklist",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon-192.png", sizes: "192x192", type: "image/png" },
    ],
    apple: "/apple-touch-icon.png",
  },
}
export default function RootLayout({ children }) {
  return <html lang="en"><body>{children}</body></html>
}
