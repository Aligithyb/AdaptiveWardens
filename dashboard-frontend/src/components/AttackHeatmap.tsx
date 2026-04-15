"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { geoMercator, geoPath } from "d3-geo";
import { select } from "d3-selection";
import { zoom, ZoomBehavior } from "d3-zoom";
import { feature } from "topojson-client";
import type { Topology } from "topojson-specification";
import type { FeatureCollection, Geometry } from "geojson";
import { Globe2, RefreshCw, AlertTriangle, Plus, Minus } from "lucide-react";

const isServer = typeof window === "undefined";
const API_URL = isServer
  ? process.env.INTERNAL_API_URL || "http://dashboard-backend:8003"
  : process.env.NEXT_PUBLIC_API_URL || "";

const GEO_URL =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface HeatmapEntry {
  country: string;
  count: number;
}

// Maps country names from ip-api.com to names used in TopoJSON
const COUNTRY_NAME_MAP: Record<string, string> = {
  "United States": "United States of America",
  Russia: "Russia",
  "South Korea": "South Korea",
  "North Korea": "North Korea",
  "Czech Republic": "Czechia",
  Iran: "Iran",
  Syria: "Syria",
  Vietnam: "Vietnam",
  "United Kingdom": "United Kingdom",
};

function normalize(name: string): string {
  return COUNTRY_NAME_MAP[name] ?? name;
}

function getColor(count: number, max: number): string {
  if (count === 0) return "#1e293b";
  const ratio = count / max;
  if (ratio < 0.2) return "#7f1d1d";
  if (ratio < 0.4) return "#991b1b";
  if (ratio < 0.6) return "#b91c1c";
  if (ratio < 0.8) return "#dc2626";
  return "#ef4444";
}

export function AttackHeatmap() {
  const [data, setData] = useState<HeatmapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [tooltip, setTooltip] = useState<{
    name: string;
    count: number;
    x: number;
    y: number;
  } | null>(null);

  const svgRef = useRef<SVGSVGElement>(null);
  const geoDataRef = useRef<FeatureCollection<Geometry> | null>(null);
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // ── Fetch API data ──────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/geo-heatmap`);
      if (!res.ok) throw new Error("Failed");
      const json = await res.json();
      setData(json.heatmap ?? []);
      setLastUpdated(new Date());
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // ── Fetch world geography once ─────────────────────────────────────
  useEffect(() => {
    fetch(GEO_URL)
      .then((r) => r.json())
      .then((topo: Topology) => {
        const countries = feature(
          topo,
          (topo as any).objects.countries
        ) as unknown as FeatureCollection<Geometry>;
        geoDataRef.current = countries;
        renderMap(countries, data);
      })
      .catch(() => {/* geo load error — silent */});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Re-render map whenever data changes ────────────────────────────
  useEffect(() => {
    if (geoDataRef.current) {
      renderMap(geoDataRef.current, data);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  // ── D3 render function ─────────────────────────────────────────────
  function renderMap(
    countries: FeatureCollection<Geometry>,
    heatmapData: HeatmapEntry[]
  ) {
    const svg = svgRef.current;
    if (!svg) return;

    const width = svg.clientWidth || 800;
    const height = svg.clientHeight || 360;

    // Build lookup
    const countryMap: Record<string, number> = {};
    let maxCount = 1;
    for (const entry of heatmapData) {
      const key = normalize(entry.country);
      countryMap[key] = entry.count;
      if (entry.count > maxCount) maxCount = entry.count;
    }

    const projection = geoMercator()
      .scale((width / 640) * 100)
      .center([0, 20])
      .translate([width / 2, height / 2]);

    const pathGen = geoPath().projection(projection);

    const svgEl = select(svg);
    // Clear previous paths
    svgEl.selectAll("*").remove();

    // Setup zoom behavior
    const zoomBehavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .translateExtent([[0, 0], [width, height]]);

    zoomBehaviorRef.current = zoomBehavior;

    // Draw background
    svgEl.append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("fill", "#020617");

    const g = svgEl.append("g");

    zoomBehavior.on("zoom", (event) => {
      g.attr("transform", event.transform);
    });

    svgEl.call(zoomBehavior);

    // Draw each country
    for (const feat of countries.features) {
      const name: string = (feat.properties as any)?.name ?? "";
      const count = countryMap[name] ?? 0;
      const fill = getColor(count, maxCount);
      const d = pathGen(feat);
      if (!d) continue;

      const path = g.append("path")
        .attr("d", d)
        .attr("fill", fill)
        .attr("stroke", "#0f172a")
        .attr("stroke-width", "0.5")
        .style("transition", "fill 0.2s")
        .style("cursor", count > 0 ? "pointer" : "default");

      if (count > 0) {
        path.on("mouseenter", (e) => {
          path.attr("fill", "#f87171");
          setTooltip({ name, count, x: e.clientX, y: e.clientY });
        });
        path.on("mousemove", (e) => {
          setTooltip((t) => (t ? { ...t, x: e.clientX, y: e.clientY } : null));
        });
        path.on("mouseleave", () => {
          path.attr("fill", fill);
          setTooltip(null);
        });
      } else {
        path.on("mouseenter", () => {
          path.attr("fill", "#334155");
        });
        path.on("mouseleave", () => {
          path.attr("fill", fill);
        });
      }
    }
  }

  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).call(zoomBehaviorRef.current.scaleBy, 1.3);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).call(zoomBehaviorRef.current.scaleBy, 1 / 1.3);
    }
  };

  const countryMap: Record<string, number> = {};
  let maxCount = 1;
  for (const entry of data) {
    const key = normalize(entry.country);
    countryMap[key] = entry.count;
    if (entry.count > maxCount) maxCount = entry.count;
  }
  const topAttackers = [...data].sort((a, b) => b.count - a.count).slice(0, 5);

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-red-500/10 rounded-lg flex items-center justify-center">
            <Globe2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h2 className="text-slate-100 font-semibold text-sm">
              Attack Origin Map
            </h2>
            <p className="text-xs text-slate-500">
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : "Loading…"}
            </p>
          </div>
        </div>
        <button
          onClick={fetchData}
          className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Map */}
      <div className="relative bg-slate-950" style={{ height: "360px" }}>
        {error && !loading && (
          <div className="absolute inset-0 flex items-center justify-center z-10">
            <div className="flex items-center gap-2 text-red-400 text-sm">
              <AlertTriangle className="w-4 h-4" />
              Could not reach API — map data unavailable
            </div>
          </div>
        )}

        <svg
          ref={svgRef}
          style={{ width: "100%", height: "360px", display: "block" }}
        />

        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 pointer-events-none px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg shadow-xl text-xs"
            style={{ left: tooltip.x + 12, top: tooltip.y - 40 }}
          >
            <p className="font-semibold text-slate-100">{tooltip.name}</p>
            <p className="text-red-400">
              {tooltip.count} attack{tooltip.count !== 1 ? "s" : ""}
            </p>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-3 left-4 flex items-center gap-2 pointer-events-none">
          <span className="text-xs text-slate-500">Low</span>
          <div className="flex">
            {["#7f1d1d", "#991b1b", "#b91c1c", "#dc2626", "#ef4444"].map(
              (c) => (
                <div
                  key={c}
                  style={{ background: c, width: 20, height: 10 }}
                />
              )
            )}
          </div>
          <span className="text-xs text-slate-500">High</span>
        </div>

        {/* Zoom Controls */}
        <div className="absolute bottom-3 right-4 flex flex-col gap-1 z-10">
          <button
            onClick={handleZoomIn}
            className="p-1.5 rounded bg-slate-800/80 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            title="Zoom In"
          >
            <Plus className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 rounded bg-slate-800/80 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            title="Zoom Out"
          >
            <Minus className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Top Attackers Table */}
      <div className="px-6 py-4 border-t border-slate-800">
        <p className="text-xs text-slate-400 font-medium mb-3 uppercase tracking-wider">
          Top Attack Origins
        </p>
        {data.length === 0 && !loading ? (
          <p className="text-xs text-slate-600 italic">
            No geo data yet — attacks will appear as sessions come in.
          </p>
        ) : (
          <div className="space-y-2">
            {topAttackers.map((entry, i) => {
              const pct = Math.round((entry.count / maxCount) * 100);
              return (
                <div key={entry.country} className="flex items-center gap-3">
                  <span className="text-xs text-slate-500 w-4">{i + 1}</span>
                  <span className="text-xs text-slate-200 w-32 truncate">
                    {entry.country}
                  </span>
                  <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-red-500 transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-red-400 w-8 text-right font-mono">
                    {entry.count}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
