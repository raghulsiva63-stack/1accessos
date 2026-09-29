"use client";

import { useEffect, useMemo, useState } from "react";
import { TrendingDown, TrendingUp } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { organizationHealthByTeam, organizationHealthTrend, type TeamHealth, type TrendPoint } from "@/lib/security/client";

const WIDTH = 640, HEIGHT = 190, PAD = { top: 12, right: 12, bottom: 24, left: 32 };

function TrendChart({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const plotted = points.map((point, index) => ({ ...point, index })).filter((point) => point.average_score !== null);
  const x = (index: number) => PAD.left + (index / Math.max(points.length - 1, 1)) * (WIDTH - PAD.left - PAD.right);
  const y = (score: number) => PAD.top + (1 - score / 100) * (HEIGHT - PAD.top - PAD.bottom);
  const line = plotted.map((point, i) => `${i === 0 ? "M" : "L"}${x(point.index).toFixed(1)},${y(point.average_score!).toFixed(1)}`).join(" ");
  const area = plotted.length ? `${line} L${x(plotted[plotted.length - 1].index).toFixed(1)},${y(0)} L${x(plotted[0].index).toFixed(1)},${y(0)} Z` : "";
  const active = hover !== null ? points[hover] : null;
  const label = (day: string) => new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

  function onMove(event: React.PointerEvent<SVGRectElement>) {
    const box = event.currentTarget.getBoundingClientRect();
    const ratio = (event.clientX - box.left) / box.width;
    const index = Math.round(ratio * (points.length - 1));
    setHover(Math.max(0, Math.min(points.length - 1, index)));
  }

  return <div className="si-chart">
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="Organization security score over time">
      <g className="grid">{[0, 50, 100].map((tick) => <line key={tick} x1={PAD.left} x2={WIDTH - PAD.right} y1={y(tick)} y2={y(tick)} />)}</g>
      <g className="axis">
        {[0, 50, 100].map((tick) => <text key={tick} x={PAD.left - 8} y={y(tick) + 4} textAnchor="end">{tick}</text>)}
        {points.length > 1 && <><text x={x(0)} y={HEIGHT - 4} textAnchor="start">{label(points[0].day)}</text><text x={x(points.length - 1)} y={HEIGHT - 4} textAnchor="end">{label(points[points.length - 1].day)}</text></>}
      </g>
      {area && <path className="area" d={area} />}
      {line && <path className="series" d={line} />}
      {plotted.length > 0 && <circle className="dot" r={4} cx={x(plotted[plotted.length - 1].index)} cy={y(plotted[plotted.length - 1].average_score!)} />}
      {active && <line className="crosshair" x1={x(hover!)} x2={x(hover!)} y1={PAD.top} y2={HEIGHT - PAD.bottom} />}
      {active?.average_score != null && <circle className="dot" r={4} cx={x(hover!)} cy={y(active.average_score)} />}
      <rect x={PAD.left} y={0} width={WIDTH - PAD.left - PAD.right} height={HEIGHT} fill="transparent" onPointerMove={onMove} onPointerLeave={() => setHover(null)} />
    </svg>
    {active && <div className="si-tooltip" style={{ left: `${(x(hover!) / WIDTH) * 100}%`, top: `${((active.average_score != null ? y(active.average_score) : y(50)) / HEIGHT) * 100}%` }}>
      {label(active.day)}<strong>{active.average_score ?? "—"}{active.average_score != null ? " / 100" : ""}</strong>
      {active.members_reporting} reporting · {active.breached} breached · {active.reused} reused
    </div>}
    <table className="sr-only"><caption>Average security score by day</caption><thead><tr><th>Day</th><th>Score</th><th>Members reporting</th></tr></thead>
      <tbody>{points.map((point) => <tr key={point.day}><td>{point.day}</td><td>{point.average_score ?? "no data"}</td><td>{point.members_reporting}</td></tr>)}</tbody></table>
  </div>;
}

/** Organization score trend (last 30 days) and the score per department. Counts only. */
export function SecurityTrend({ tenantId }: { tenantId: string }) {
  const [points, setPoints] = useState<TrendPoint[]>([]);
  const [teams, setTeams] = useState<TeamHealth[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "unavailable">("loading");
  useEffect(() => {
    let active = true;
    void Promise.all([organizationHealthTrend(tenantId, 30), organizationHealthByTeam(tenantId)]).then(
      ([trend, byTeam]) => { if (active) { setPoints(trend); setTeams(byTeam); setState("ready"); } },
      () => { if (active) setState("unavailable"); });
    return () => { active = false; };
  }, [tenantId]);

  const change = useMemo(() => {
    const scored = points.filter((point) => point.average_score !== null);
    if (scored.length < 2) return null;
    return scored[scored.length - 1].average_score! - scored[0].average_score!;
  }, [points]);
  const latest = [...points].reverse().find((point) => point.average_score !== null);

  if (state === "unavailable") return null;
  return <div className="si-grid-2">
    <Card>
      <CardHeader><CardTitle>Security score trend</CardTitle>
        <CardDescription>{latest ? <>Now <strong>{latest.average_score}/100</strong> across {latest.members_reporting} member{latest.members_reporting === 1 ? "" : "s"}{change !== null && <> · {change >= 0 ? <TrendingUp className="inline-icon" /> : <TrendingDown className="inline-icon" />} {change >= 0 ? "+" : ""}{change} in 30 days</>}</> : "Scores appear as members open their vaults."}</CardDescription></CardHeader>
      <CardContent>{state === "loading" ? <div className="loading-ring" /> : <TrendChart points={points} />}</CardContent>
    </Card>
    <Card>
      <CardHeader><CardTitle>By team</CardTitle><CardDescription>Lowest scores first. Set departments in Directory.</CardDescription></CardHeader>
      <CardContent>{state === "loading" ? <div className="loading-ring" /> : <div className="si-table-wrap"><table className="si-table">
        <thead><tr><th>Team</th><th className="num">Score</th><th className="num">Reporting</th><th className="num">Breached</th><th className="num">Reused</th></tr></thead>
        <tbody>{teams.map((team) => <tr key={team.department_id ?? "none"}>
          <td>{team.department_name}</td>
          <td className="num">{team.average_score === null ? "—" : <span className={`score-badge ${team.average_score >= 80 ? "good" : team.average_score >= 60 ? "warn" : "bad"}`}>{team.average_score}</span>}</td>
          <td className="num">{team.members_reporting}/{team.members}</td><td className="num">{team.breached}</td><td className="num">{team.reused}</td>
        </tr>)}</tbody>
      </table></div>}</CardContent>
    </Card>
  </div>;
}
