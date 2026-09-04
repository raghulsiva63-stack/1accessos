import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Passkey-X — Your private digital vault",
  description: "Zero-knowledge password, passkey, credential, and recovery vault by Vlightsoft.",
  applicationName: "Passkey-X",
  manifest: "/manifest.webmanifest",
  icons: { icon: "/favicon.png", shortcut: "/favicon-16.png", apple: "/brand/passkey-x-app-icon.png" },
};
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
