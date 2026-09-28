import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/legal-page";
import { PRIVACY } from "@/lib/legal/content";

export const metadata: Metadata = {
  title: "Privacy Policy — Passkey-X",
  description: "How Passkey-X collects, uses and protects personal data. Your vault is encrypted on your device and we cannot read it.",
};

export default function Page() {
  return <LegalPage document={PRIVACY} />;
}
