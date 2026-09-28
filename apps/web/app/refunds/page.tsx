import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/legal-page";
import { REFUNDS } from "@/lib/legal/content";

export const metadata: Metadata = {
  title: "Refund & Cancellation Policy — Passkey-X",
  description: "Cancel any time and get a full refund within 30 days of your first payment.",
};

export default function Page() {
  return <LegalPage document={REFUNDS} />;
}
