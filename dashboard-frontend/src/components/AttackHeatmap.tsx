"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { select } from "d3-selection";
import { zoom, ZoomBehavior, zoomIdentity } from "d3-zoom";
import { feature } from "topojson-client";
import type { Topology } from "topojson-specification";
import type { FeatureCollection, Geometry } from "geojson";
import { Globe2, RefreshCw, AlertTriangle, Plus, Minus, Home } from "lucide-react";

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

interface LivePin {
  session_id: string;
  country: string;
  risk_level: string;
  threat_score: number;
  start_time: string;
  protocol: string;
}

// Approximate [lon, lat] centroids for common attacker origins
const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  "United States of America": [-98, 38], "China": [104, 35], "Russia": [100, 60],
  "Germany": [10, 51], "United Kingdom": [-2, 54], "France": [2, 46],
  "Brazil": [-53, -10], "India": [78, 20], "Netherlands": [5, 52],
  "Canada": [-95, 60], "Australia": [135, -25], "Japan": [138, 36],
  "South Korea": [128, 36], "Italy": [12, 42], "Sweden": [15, 62],
  "Ukraine": [32, 49], "Poland": [20, 52], "Spain": [-3, 40],
  "Turkey": [35, 39], "Iran": [53, 32], "Romania": [25, 46],
  "Vietnam": [108, 16], "Indonesia": [120, -5], "Mexico": [-102, 23],
  "Thailand": [101, 15], "Pakistan": [69, 30], "Egypt": [30, 26],
  "Nigeria": [8, 10], "South Africa": [25, -29], "Argentina": [-64, -34],
  "Singapore": [104, 1], "Malaysia": [110, 3], "Taiwan": [121, 24],
  "Hong Kong": [114, 22], "Bangladesh": [90, 24], "Bulgaria": [25, 43],
  "Czech Republic": [16, 50], "Czechia": [16, 50], "Hungary": [19, 47],
  "Austria": [14, 47], "Switzerland": [8, 47], "Belgium": [4, 50],
  "Portugal": [-8, 39], "Greece": [22, 38], "Denmark": [10, 56],
  "Norway": [10, 62], "Finland": [26, 64], "Lithuania": [24, 56],
  "Latvia": [25, 57], "Estonia": [25, 59], "Belarus": [28, 53],
  "Moldova": [29, 47], "Kazakhstan": [68, 48], "Uzbekistan": [63, 41],
  "Azerbaijan": [47, 40], "Georgia": [44, 42], "Armenia": [45, 40],
  "Iraq": [44, 33], "Saudi Arabia": [45, 24], "United Arab Emirates": [54, 24],
  "Israel": [35, 31], "Lebanon": [36, 34], "Jordan": [37, 31],
  "Ethiopia": [40, 9], "Kenya": [38, 1], "Tanzania": [35, -6],
  "Ghana": [-2, 8], "Senegal": [-14, 14], "Morocco": [-5, 32],
  "Algeria": [3, 28], "Tunisia": [9, 34], "Libya": [17, 27],
  "Sudan": [30, 15], "Somalia": [46, 6], "Venezuela": [-66, 8],
  "Colombia": [-74, 4], "Chile": [-71, -30], "Peru": [-76, -10],
  "Bolivia": [-64, -17], "Paraguay": [-58, -23], "Uruguay": [-56, -33],
  "Philippines": [122, 13], "Myanmar": [96, 17], "Cambodia": [105, 12],
  "Laos": [103, 18], "New Zealand": [172, -41], "Nepal": [84, 28],
  "Sri Lanka": [81, 7], "Afghanistan": [67, 33], "Mongolia": [105, 46],
  "Unknown": [0, 0],
};

function pinColor(riskLevel: string): string {
  switch (riskLevel) {
    case 'Critical': return '#ef4444';
    case 'High':     return '#f97316';
    case 'Medium':   return '#eab308';
    default:         return '#3b82f6';
  }
}

const ISO_TO_NAME: Record<string, string> = {
  AF: "Afghanistan", AL: "Albania", DZ: "Algeria", AO: "Angola",
  AR: "Argentina", AM: "Armenia", AU: "Australia", AT: "Austria",
  AZ: "Azerbaijan", BS: "Bahamas", BD: "Bangladesh", BY: "Belarus",
  BE: "Belgium", BZ: "Belize", BJ: "Benin", BT: "Bhutan",
  BO: "Bolivia", BA: "Bosnia and Herz.", BW: "Botswana", BR: "Brazil",
  BN: "Brunei", BG: "Bulgaria", BF: "Burkina Faso", BI: "Burundi",
  KH: "Cambodia", CM: "Cameroon", CA: "Canada", CF: "Central African Rep.",
  TD: "Chad", CL: "Chile", CN: "China", CO: "Colombia",
  CG: "Congo", CD: "Dem. Rep. Congo", CR: "Costa Rica", HR: "Croatia",
  CU: "Cuba", CY: "Cyprus", CZ: "Czechia", DK: "Denmark",
  DJ: "Djibouti", DO: "Dominican Rep.", EC: "Ecuador", EG: "Egypt",
  SV: "El Salvador", GQ: "Eq. Guinea", ER: "Eritrea", EE: "Estonia",
  SZ: "eSwatini", ET: "Ethiopia", FJ: "Fiji", FI: "Finland",
  FR: "France", GA: "Gabon", GM: "Gambia", GE: "Georgia",
  DE: "Germany", GH: "Ghana", GR: "Greece", GT: "Guatemala",
  GN: "Guinea", GW: "Guinea-Bissau", GY: "Guyana", HT: "Haiti",
  HN: "Honduras", HU: "Hungary", IS: "Iceland", IN: "India",
  ID: "Indonesia", IR: "Iran", IQ: "Iraq", IE: "Ireland",
  IL: "Israel", IT: "Italy", CI: "Côte d'Ivoire", JM: "Jamaica",
  JP: "Japan", JO: "Jordan", KZ: "Kazakhstan", KE: "Kenya",
  KP: "North Korea", KR: "South Korea", XK: "Kosovo", KW: "Kuwait",
  KG: "Kyrgyzstan", LA: "Laos", LV: "Latvia", LB: "Lebanon",
  LS: "Lesotho", LR: "Liberia", LY: "Libya", LT: "Lithuania",
  LU: "Luxembourg", MK: "Macedonia", MG: "Madagascar", MW: "Malawi",
  MY: "Malaysia", ML: "Mali", MR: "Mauritania", MX: "Mexico",
  MD: "Moldova", MN: "Mongolia", ME: "Montenegro", MA: "Morocco",
  MZ: "Mozambique", MM: "Myanmar", NA: "Namibia", NP: "Nepal",
  NL: "Netherlands", NZ: "New Zealand", NI: "Nicaragua", NE: "Niger",
  NG: "Nigeria", NO: "Norway", OM: "Oman", PK: "Pakistan",
  PS: "Palestine", PA: "Panama", PG: "Papua New Guinea", PY: "Paraguay",
  PE: "Peru", PH: "Philippines", PL: "Poland", PT: "Portugal",
  QA: "Qatar", RO: "Romania", RU: "Russia", RW: "Rwanda",
  SA: "Saudi Arabia", SN: "Senegal", RS: "Serbia", SL: "Sierra Leone",
  SK: "Slovakia", SI: "Slovenia", SB: "Solomon Is.", SO: "Somalia",
  ZA: "South Africa", SS: "S. Sudan", ES: "Spain", LK: "Sri Lanka",
  SD: "Sudan", SR: "Suriname", SE: "Sweden", CH: "Switzerland",
  SY: "Syria", TW: "Taiwan", TJ: "Tajikistan", TZ: "Tanzania",
  TH: "Thailand", TL: "Timor-Leste", TG: "Togo", TT: "Trinidad and Tobago",
  TN: "Tunisia", TR: "Turkey", TM: "Turkmenistan", UG: "Uganda",
  UA: "Ukraine", AE: "United Arab Emirates", GB: "United Kingdom",
  US: "United States of America", UY: "Uruguay", UZ: "Uzbekistan",
  VU: "Vanuatu", VE: "Venezuela", VN: "Vietnam", EH: "W. Sahara",
  YE: "Yemen", ZM: "Zambia", ZW: "Zimbabwe",
};

const COUNTRY_NAME_MAP: Record<string, string> = {
  "United States": "United States of America",
  USA: "United States of America",
  "Czech Republic": "Czechia",
  "Ivory Coast": "Côte d'Ivoire",
  "East Timor": "Timor-Leste",
  "Democratic Republic of the Congo": "Dem. Rep. Congo",
  DRC: "Dem. Rep. Congo",
  "Congo [DRC]": "Dem. Rep. Congo",
  "Republic of the Congo": "Congo",
  "Congo [Republic]": "Congo",
  "North Macedonia": "Macedonia",
  "Bosnia and Herzegovina": "Bosnia and Herz.",
  "Central African Republic": "Central African Rep.",
  "Equatorial Guinea": "Eq. Guinea",
  "South Sudan": "S. Sudan",
  "Dominican Republic": "Dominican Rep.",
  "Falkland Islands": "Falkland Is.",
  "Solomon Islands": "Solomon Is.",
  "Western Sahara": "W. Sahara",
  Eswatini: "eSwatini",
  Swaziland: "eSwatini",
  "Russian Federation": "Russia",
  "Syrian Arab Republic": "Syria",
  "Viet Nam": "Vietnam",
  "Brunei Darussalam": "Brunei",
  "Lao People's Democratic Republic": "Laos",
  "United Republic of Tanzania": "Tanzania",
  Burma: "Myanmar",
  "Myanmar (Burma)": "Myanmar",
  "The Bahamas": "Bahamas",
  "The Gambia": "Gambia",
  Palestine: "Palestine",
  "The Netherlands": "Netherlands",
  "United Kingdom of Great Britain and Northern Ireland": "United Kingdom",
  "Republic of Korea": "South Korea",
  Korea: "South Korea",
  "Democratic People's Republic of Korea": "North Korea",
  "Cabo Verde": "Cape Verde",
};

function normalize(name: string): string {
  const isoMapped = ISO_TO_NAME[name.toUpperCase()];
  if (isoMapped) return isoMapped;
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
  const [livePins, setLivePins] = useState<LivePin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [showPins, setShowPins] = useState(true);
  const [tooltip, setTooltip] = useState<{
    name: string;
    count: number;
    x: number;
    y: number;
  } | null>(null);

  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const geoDataRef = useRef<FeatureCollection<Geometry> | null>(null);
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // ── Fetch heatmap data ──────────────────────────────────────────────
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

  // ── Fetch live session pins ─────────────────────────────────────────
  const fetchPins = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/map/live-sessions`);
      if (!res.ok) return;
      const json = await res.json();
      setLivePins(json.sessions ?? []);
    } catch { /* non-fatal */ }
  }, []);

  useEffect(() => {
    fetchData();
    fetchPins();
    const i1 = setInterval(fetchData, 30_000);
    const i2 = setInterval(fetchPins, 10_000);
    return () => { clearInterval(i1); clearInterval(i2); };
  }, [fetchData, fetchPins]);

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
        renderMap(countries, data, livePins, showPins);
      })
      .catch(() => {/* geo load error — silent */});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Re-render map whenever data or pins change ─────────────────────
  useEffect(() => {
    if (geoDataRef.current) renderMap(geoDataRef.current, data, livePins, showPins);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, livePins, showPins]);

  // ── ResizeObserver – re-render on container resize ─────────────────
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(() => {
      if (geoDataRef.current) renderMap(geoDataRef.current, data, livePins, showPins);
    });
    observer.observe(el);
    return () => observer.disconnect();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, livePins, showPins]);

  // ── D3 render function ─────────────────────────────────────────────
  function renderMap(
    countries: FeatureCollection<Geometry>,
    heatmapData: HeatmapEntry[],
    pins: LivePin[] = [],
    drawPins: boolean = true
  ) {
    const svg = svgRef.current;
    if (!svg) return;

    const width = svg.clientWidth || 900;
    const height = svg.clientHeight || 520;

    // Build lookup
    const countryMap: Record<string, number> = {};
    let maxCount = 1;
    for (const entry of heatmapData) {
      const key = normalize(entry.country);
      countryMap[key] = entry.count;
      if (entry.count > maxCount) maxCount = entry.count;
    }

    // Natural Earth projection – shows all countries including Antarctica
    const projection = geoNaturalEarth1()
      .scale((width / 640) * 100)
      .translate([width / 2, height / 2]);

    const pathGen = geoPath().projection(projection);

    const svgEl = select(svg);
    svgEl.selectAll("*").remove();

    // Zoom behaviour with generous translate extent
    const zoomBehavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 12])
      .translateExtent([[-width * 0.5, -height * 0.5], [width * 1.5, height * 1.5]])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    zoomBehaviorRef.current = zoomBehavior;

    // Background
    svgEl.append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("fill", "#020617");

    const g = svgEl.append("g");

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

    // ── Live session pins ──────────────────────────────────────────
    if (drawPins && pins.length > 0) {
      // Dedupe by country, keeping the highest-risk entry
      const byCountry = new Map<string, LivePin>();
      for (const pin of pins) {
        const existing = byCountry.get(pin.country);
        if (!existing || pin.threat_score > (existing.threat_score ?? 0)) {
          byCountry.set(pin.country, pin);
        }
      }

      for (const [country, pin] of byCountry) {
        const normalized = COUNTRY_NAME_MAP[country] ?? country;
        let centroid = COUNTRY_CENTROIDS[normalized] ?? COUNTRY_CENTROIDS[country];
        if (!centroid) continue;

        const projected = projection(centroid);
        if (!projected) continue;
        const [px, py] = projected;
        const col = pinColor(pin.risk_level);

        // Outer pulse ring
        g.append("circle")
          .attr("cx", px).attr("cy", py)
          .attr("r", 7)
          .attr("fill", col)
          .attr("opacity", 0.25)
          .style("pointer-events", "none");

        // Inner dot
        g.append("circle")
          .attr("cx", px).attr("cy", py)
          .attr("r", 3.5)
          .attr("fill", col)
          .attr("stroke", "#0f172a")
          .attr("stroke-width", 1)
          .style("pointer-events", "none");
      }
    }
  }

  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).call(zoomBehaviorRef.current.scaleBy, 1.4);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).call(zoomBehaviorRef.current.scaleBy, 1 / 1.4);
    }
  };

  const handleReset = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).call(zoomBehaviorRef.current.transform, zoomIdentity);
    }
  };

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
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
                : loading ? "Loading…" : "—"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!loading && data.length > 0 && (
            <span className="text-xs text-slate-400 mr-2">
              {data.length} countr{data.length !== 1 ? "ies" : "y"} with attacks
            </span>
          )}
          {livePins.length > 0 && (
            <button
              onClick={() => setShowPins(p => !p)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs transition-colors border ${
                showPins
                  ? 'bg-red-500/10 border-red-500/30 text-red-400'
                  : 'bg-slate-800 border-slate-700 text-slate-500'
              }`}
              title="Toggle live session pins"
            >
              <span className={`w-2 h-2 rounded-full ${showPins ? 'bg-red-400 animate-pulse' : 'bg-slate-600'}`} />
              {livePins.length} live
            </button>
          )}
          <button
            onClick={() => { fetchData(); fetchPins(); }}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Map */}
      <div
        ref={containerRef}
        className="relative bg-slate-950 flex-1"
        style={{ minHeight: "520px" }}
      >
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
          style={{ width: "100%", height: "100%", display: "block", minHeight: "520px" }}
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
        <div className="absolute bottom-4 left-4 flex items-center gap-2 pointer-events-none">
          <span className="text-xs text-slate-500">Low</span>
          <div className="flex rounded overflow-hidden">
            {["#7f1d1d", "#991b1b", "#b91c1c", "#dc2626", "#ef4444"].map(
              (c) => (
                <div
                  key={c}
                  style={{ background: c, width: 22, height: 10 }}
                />
              )
            )}
          </div>
          <span className="text-xs text-slate-500">High</span>
        </div>

        {/* Zoom + Reset Controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-1 z-10">
          <button
            onClick={handleZoomIn}
            className="p-1.5 rounded bg-slate-800/90 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            title="Zoom In"
          >
            <Plus className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 rounded bg-slate-800/90 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            title="Zoom Out"
          >
            <Minus className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            className="p-1.5 rounded bg-slate-800/90 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            title="Reset View"
          >
            <Home className="w-4 h-4" />
          </button>
        </div>

        {/* Hint */}
        <div className="absolute top-3 right-4 text-xs text-slate-600 pointer-events-none select-none">
          Scroll to zoom · Drag to pan
        </div>
      </div>
    </div>
  );
}
