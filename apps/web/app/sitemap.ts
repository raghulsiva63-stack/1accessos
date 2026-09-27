import type { MetadataRoute } from "next";
import { PRODUCTS, SOLUTIONS } from "@/lib/marketing/catalog";

export const dynamic = "force-static";

const SITE = "https://passkey-x.com";
const PAGES: { path: string; priority: number }[] = [
  { path: "/", priority: 1 },
  { path: "/pricing", priority: 0.9 },
  { path: "/enterprise", priority: 0.9 },
  { path: "/security", priority: 0.9 },
  ...PRODUCTS.map((entry) => ({ path: `/products/${entry.slug}`, priority: 0.8 })),
  ...SOLUTIONS.map((entry) => ({ path: `/solutions/${entry.slug}`, priority: 0.7 })),
  { path: "/compare", priority: 0.7 },
  { path: "/contact", priority: 0.7 },
  { path: "/download", priority: 0.6 },
  { path: "/api-docs", priority: 0.5 },
];

export default function sitemap(): MetadataRoute.Sitemap {
  return PAGES.map((page) => ({ url: `${SITE}${page.path}`, changeFrequency: "weekly", priority: page.priority }));
}
