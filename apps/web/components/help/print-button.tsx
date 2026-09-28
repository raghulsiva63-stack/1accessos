"use client";

import { Printer } from "lucide-react";

export function PrintButton() {
  return <button type="button" className="public-secondary-link help-print" onClick={() => window.print()}><Printer /> Print or save as PDF</button>;
}
