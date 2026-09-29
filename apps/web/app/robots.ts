import type { MetadataRoute } from "next";

export const dynamic = "force-static";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/", disallow: ["/send", "/app/", "/extension/", "/desktop-link/"] }],
    sitemap: "https://passkey-x.com/sitemap.xml",
  };
}
