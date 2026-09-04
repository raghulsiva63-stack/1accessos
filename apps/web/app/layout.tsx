import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "1accessos — Secure vault",
  description: "Zero-knowledge credential and access management.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
