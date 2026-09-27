import type { Metadata, Viewport } from "next";
import { AppRuntime } from "@/components/app-install";
import "./globals.css";
import "./clients.css";
import "./enterprise.css";
import "./marketing.css";
import "./marketing-nav.css";
import "./app-features.css";

export const metadata: Metadata = {
  title: "Passkey-X — Your private digital vault",
  description: "Zero-knowledge password, passkey, credential, and recovery vault by Vlightsoft.",
  applicationName: "Passkey-X",
  manifest: "/manifest.webmanifest",
  appleWebApp: { capable: true, statusBarStyle: "black-translucent", title: "Passkey-X" },
  icons: { icon: "/favicon.png", shortcut: "/favicon-16.png", apple: "/brand/passkey-x-app-icon.png" },
};
export const viewport: Viewport = { width: "device-width", initialScale: 1, viewportFit: "cover", themeColor: "#050b1f" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body><AppRuntime />{children}</body></html>; }
