// Security notification templates. Pure functions (no Deno or network access) so they can be
// unit-tested. Every value from the database is escaped for HTML and never contains secrets:
// the outbox only carries device labels, network prefixes, country codes, alert titles, breach
// names and counts.

export type RenderedNotification = { subject: string; text: string; html: string; sms: string | null };

type Params = Record<string, unknown>;

const COUNTRY = /^[A-Z]{2}$/u;

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

function text(value: unknown, fallback: string, max = 160): string {
  if (typeof value !== "string") return fallback;
  // Drop control characters and collapse whitespace so a value can't forge extra lines.
  const cleaned = value.replace(/[\u0000-\u001f\u007f]+/gu, " ").replace(/\s+/gu, " ").trim();
  return cleaned ? cleaned.slice(0, max) : fallback;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value < 10_000_000 ? value : null;
}

function when(value: unknown): string {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (Number.isNaN(parsed)) return "just now";
  return `${new Date(parsed).toISOString().replace("T", " ").slice(0, 16)} UTC`;
}

export const RISK_LABELS: Record<string, string> = {
  critical_alerts: "open critical alerts",
  high_alerts: "open high-severity alerts",
  breached_passwords: "passwords found in known breaches",
  members_in_breaches: "people whose email appeared in a breach with passwords",
  exposed_secrets: "secrets stored in notes or the wrong item type",
  members_without_two_step: "people without two-step verification",
  reused_passwords: "reused passwords",
  lookalike_sites: "saved logins for look-alike websites",
  weak_passwords: "weak passwords",
  rotation_overdue: "overdue password rotations",
  members_not_reporting: "people whose vault health has not been reported yet",
};

function layout(appUrl: string, heading: string, paragraphs: string[], action?: { label: string; path: string }): string {
  const body = paragraphs.map((paragraph) => `<p style="margin:0 0 14px;line-height:1.5">${paragraph}</p>`).join("");
  const button = action
    ? `<p style="margin:22px 0"><a href="${escapeHtml(appUrl + action.path)}" style="background:#1f4fd8;color:#ffffff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:600">${escapeHtml(action.label)}</a></p>`
    : "";
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f6f8;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#15181e">`
    + `<div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:28px">`
    + `<p style="margin:0 0 18px;font-weight:700;color:#1f4fd8">Passkey-X</p>`
    + `<h1 style="font-size:20px;margin:0 0 16px">${escapeHtml(heading)}</h1>${body}${button}`
    + `<p style="margin:24px 0 0;font-size:12px;color:#5b6270">Passkey-X never asks for your passwords by email. Change which security emails you get in Account security → Notifications.</p>`
    + `</div></body></html>`;
}

function plain(heading: string, lines: string[], appUrl: string, path?: string): string {
  return [heading, "", ...lines, ...(path ? ["", `${appUrl}${path}`] : []), "",
    "Passkey-X never asks for your passwords by email."].join("\n");
}

/** Renders one outbox entry. Unknown templates return null (the worker marks them skipped). */
export function renderNotification(template: string, params: Params, appUrl = "https://passkey-x.com"): RenderedNotification | null {
  const device = escapeHtml(text(params.device, "an unknown device", 60));
  const network = escapeHtml(text(params.network, "an unknown network", 60));
  switch (template) {
    case "new_sign_in": {
      const heading = "New sign-in to your Passkey-X account";
      const lines = [`${text(params.device, "An unknown device", 60)} signed in from network ${text(params.network, "unknown", 60)} at ${when(params.at)}.`,
        "If this was you, there is nothing to do.",
        "If it wasn't, open Account security → Sign-in activity, sign out that session and change your account password."];
      return {
        subject: heading,
        text: plain(heading, lines, appUrl, "/?view=account-security"),
        html: layout(appUrl, heading, [`<strong>${device}</strong> signed in from network <strong>${network}</strong> at ${escapeHtml(when(params.at))}.`,
          "If this was you, there is nothing to do.",
          "If it wasn’t you, sign out that session in <strong>Account security → Sign-in activity</strong> and change your account password. Your vault stays encrypted: a sign-in alone cannot open it."],
          { label: "Review sign-in activity", path: "/?view=account-security" }),
        sms: `Passkey-X: new sign-in from ${text(params.device, "an unknown device", 40)}. Not you? Review Sign-in activity now.`,
      };
    }
    case "new_country": {
      const country = typeof params.country === "string" && COUNTRY.test(params.country) ? params.country : "another country";
      const heading = `Sign-in from a new country (${country})`;
      return {
        subject: heading,
        text: plain(heading, [`${text(params.device, "A device", 60)} signed in from ${country}. If this wasn't you, sign out that session and change your account password.`], appUrl, "/?view=account-security"),
        html: layout(appUrl, heading, [`<strong>${device}</strong> signed in to your account from <strong>${escapeHtml(country)}</strong> for the first time.`,
          "If this wasn’t you, sign out that session and change your account password."], { label: "Review sign-in activity", path: "/?view=account-security" }),
        sms: `Passkey-X: sign-in from a new country (${country}). Not you? Review Sign-in activity now.`,
      };
    }
    case "many_networks": {
      const networks = count(params.networks) ?? 4;
      const heading = "Unusual sign-in activity";
      return {
        subject: heading,
        text: plain(heading, [`Your account signed in from ${networks} different networks within an hour. If this wasn't you, sign out all other sessions and change your account password now.`], appUrl, "/?view=account-security"),
        html: layout(appUrl, heading, [`Your account signed in from <strong>${networks} different networks</strong> within an hour.`,
          "If this wasn’t you, choose <strong>Sign out everywhere else</strong> in Sign-in activity and change your account password now."],
          { label: "Review sign-in activity", path: "/?view=account-security" }),
        sms: `Passkey-X: sign-ins from ${networks} networks in an hour. Not you? Sign out other sessions now.`,
      };
    }
    case "security_alert": {
      const title = text(params.title, "A security alert was raised", 160);
      const severity = ["critical", "high", "medium", "low"].includes(String(params.severity)) ? String(params.severity) : "high";
      const heading = `${severity === "critical" ? "Critical" : "High"} security alert: ${title}`;
      return {
        subject: heading.slice(0, 140),
        text: plain(heading, ["Open the Admin console → Alerts to review it, acknowledge it, and ask the AI triage for next steps."], appUrl, "/?view=admin&tab=alerts"),
        html: layout(appUrl, "Security alert for your organization", [`<strong>${escapeHtml(title)}</strong> (${escapeHtml(severity)}).`,
          "Review it in the Admin console. Alerts contain metadata only — never passwords or vault content."],
          { label: "Open alerts", path: "/?view=admin&tab=alerts" }),
        sms: `Passkey-X ${severity} alert: ${title.slice(0, 90)}. Review it in Admin > Alerts.`,
      };
    }
    case "breach_exposure": {
      const breach = text(params.breach, "a data breach", 160);
      const passwords = params.includes_passwords === true;
      const heading = "Your email appeared in a data breach";
      const advice = passwords
        ? "The breach included passwords. If you used the same password anywhere else, change it now — Security → Fix your passwords walks you through it."
        : "Watch for phishing emails that mention this service, and make sure your password there is unique.";
      return {
        subject: heading,
        text: plain(heading, [`Have I Been Pwned lists your work email in the breach "${breach}".`, advice], appUrl, "/?view=security"),
        html: layout(appUrl, heading, [`Have I Been Pwned lists your work email in the breach <strong>${escapeHtml(breach)}</strong>.`, escapeHtml(advice)],
          { label: "Check my passwords", path: "/?view=security" }),
        sms: null,
      };
    }
    case "passkey_nudge": {
      const heading = "Your organization asks you to add a passkey";
      return {
        subject: heading,
        text: plain(heading, ["A passkey lets you sign in with your fingerprint, face or device PIN and can't be phished. It takes about a minute: Account security → Add passkey."], appUrl, "/?view=account-security"),
        html: layout(appUrl, heading, ["A passkey lets you sign in with your fingerprint, face or device PIN. It can’t be phished or reused on a fake site.",
          "It takes about a minute: open <strong>Account security</strong> and choose <strong>Add passkey</strong>."],
          { label: "Add a passkey", path: "/?view=account-security" }),
        sms: null,
      };
    }
    case "rotation_assigned": {
      const title = text(params.title, "Password rotation", 120);
      const items = count(params.count) ?? 1;
      const due = typeof params.due === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(params.due) ? params.due : "soon";
      const heading = `Please change ${items} password${items === 1 ? "" : "s"} by ${due}`;
      return {
        subject: heading,
        text: plain(heading, [`Your administrator started "${title}". Open Security → Rotation tasks to change each password; tasks complete automatically when you save.`], appUrl, "/?view=security"),
        html: layout(appUrl, heading, [`Your administrator started <strong>${escapeHtml(title)}</strong>.`,
          "Open <strong>Security → Rotation tasks</strong>. For each item, generate a new password, change it on the website and save it — the task completes automatically."],
          { label: "Open rotation tasks", path: "/?view=security" }),
        sms: null,
      };
    }
    case "weekly_report": {
      const score = count(params.score);
      const previous = count(params.score_week_ago);
      const trend = score === null ? "No vault health reports yet."
        : previous === null ? `Organization security score: ${score}/100.`
        : `Organization security score: ${score}/100 (${score >= previous ? "+" : ""}${score - previous} since last week).`;
      const risks = Array.isArray(params.top_risks) ? params.top_risks.slice(0, 3).flatMap((risk) => {
        if (!risk || typeof risk !== "object") return [];
        const entry = risk as { key?: unknown; count?: unknown };
        const label = typeof entry.key === "string" ? RISK_LABELS[entry.key] : undefined;
        const value = count(entry.count);
        return label && value !== null ? [`${value.toLocaleString("en-US")} ${label}`] : [];
      }) : [];
      const alerts = count(params.alerts_new_7d) ?? 0;
      const heading = "Your weekly Passkey-X security report";
      const riskText = risks.length ? risks.map((risk, index) => `${index + 1}. ${risk}`) : ["No major risks this week."];
      return {
        subject: score === null ? heading : `${heading}: score ${score}/100`,
        text: plain(heading, [trend, `${alerts} new alert${alerts === 1 ? "" : "s"} this week.`, "Top risks:", ...riskText], appUrl, "/?view=admin&tab=reports"),
        html: layout(appUrl, heading, [escapeHtml(trend), `${alerts} new alert${alerts === 1 ? "" : "s"} this week.`,
          `<strong>Top risks</strong><br>${risks.length ? risks.map((risk, index) => `${index + 1}. ${escapeHtml(risk)}`).join("<br>") : "No major risks this week."}`,
          "Open the report for the AI summary, the trend chart and a PDF for your records."],
          { label: "Open the full report", path: "/?view=admin&tab=reports" }),
        sms: null,
      };
    }
    default:
      return null;
  }
}

/** Only these events may go out by SMS (and only where the organization set SMS up). */
export const SMS_EVENTS = new Set(["new_device", "security_alert"]);
