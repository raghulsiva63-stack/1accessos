import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { EntryPage } from "@/components/marketing/entry-page";
import { findSolution, SOLUTIONS } from "@/lib/marketing/catalog";

export const dynamicParams = false;

export function generateStaticParams() {
  return SOLUTIONS.map((entry) => ({ slug: entry.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const entry = findSolution((await params).slug);
  return entry ? { title: entry.metaTitle, description: entry.metaDescription } : {};
}

export default async function SolutionPage({ params }: { params: Promise<{ slug: string }> }) {
  const entry = findSolution((await params).slug);
  if (!entry) notFound();
  return <EntryPage entry={entry} />;
}
