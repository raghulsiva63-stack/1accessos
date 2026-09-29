import type { Metadata } from "next";
import { DesktopLinkApproval } from "@/components/desktop/desktop-link";

export const metadata: Metadata = {
  title: "Sign in to Passkey-X desktop",
  robots: { index: false, follow: false },
};

export default function DesktopLinkPage() {
  return <DesktopLinkApproval />;
}
