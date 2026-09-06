const DEFAULT_REVOKE_DELAY_MS = 60_000;

type DownloadAnchor = {
  href: string;
  download: string;
  rel: string;
  style: { display: string };
  click: () => void;
  remove: () => void;
};

type DownloadDocument = {
  body: { append: (anchor: DownloadAnchor) => void };
  createElement: (name: "a") => DownloadAnchor;
};

type DownloadUrl = {
  createObjectURL: (blob: Blob) => string;
  revokeObjectURL: (url: string) => void;
};

type DownloadOptions = {
  documentObject?: DownloadDocument;
  urlObject?: DownloadUrl;
  schedule?: (callback: () => void, delayMs: number) => unknown;
  revokeDelayMs?: number;
};

/**
 * Starts a browser download from a Blob.
 *
 * The anchor is attached to the document and the object URL stays alive long
 * enough for Safari and hardened browsers to consume it. Revoking the URL in
 * the same task as `click()` can silently cancel the download.
 */
export function downloadBlob(
  blob: Blob,
  filename: string,
  options: DownloadOptions = {},
) {
  if (!filename.trim() || /[\\/\0]/u.test(filename)) {
    throw new Error("A safe download filename is required.");
  }

  const documentObject: DownloadDocument = options.documentObject
    ?? (document as unknown as DownloadDocument);
  const urlObject: DownloadUrl = options.urlObject ?? URL;
  const schedule = options.schedule ?? globalThis.setTimeout;
  const objectUrl = urlObject.createObjectURL(blob);
  const anchor = documentObject.createElement("a");

  try {
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.style.display = "none";
    documentObject.body.append(anchor);
    anchor.click();
  } catch (reason) {
    urlObject.revokeObjectURL(objectUrl);
    throw reason;
  } finally {
    anchor.remove();
  }

  schedule(
    () => urlObject.revokeObjectURL(objectUrl),
    options.revokeDelayMs ?? DEFAULT_REVOKE_DELAY_MS,
  );
}
