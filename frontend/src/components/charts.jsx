import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITIES, SEVERITY_COLORS, compactNumber, formatNumber, shortDay } from "../utils.js";

const AXIS_STYLE = { fill: "#8399b8", fontSize: 11 };
const TOOLTIP_STYLE = {
  background: "#0b1524",
  border: "1px solid #22324b",
  borderRadius: 10,
  color: "#e7eefb",
  fontSize: 12,
  boxShadow: "0 18px 40px rgba(0,0,0,.45)",
};
const LABEL_STYLE = { color: "#e7eefb", fontWeight: 600, marginBottom: 4 };
const ITEM_STYLE = { color: "#c3d3e8" };

export function TrendChart({ data = [] }) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          {SEVERITIES.map((severity) => (
            <linearGradient key={severity} id={`fill-${severity}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={SEVERITY_COLORS[severity]} stopOpacity={0.55} />
              <stop offset="100%" stopColor={SEVERITY_COLORS[severity]} stopOpacity={0.04} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke="#152134" strokeDasharray="3 6" vertical={false} />
        <XAxis
          dataKey="date"
          tickFormatter={shortDay}
          tick={AXIS_STYLE}
          axisLine={{ stroke: "#1a2940" }}
          tickLine={false}
          minTickGap={22}
        />
        <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} allowDecimals={false} width={44} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelStyle={LABEL_STYLE}
          itemStyle={ITEM_STYLE}
          labelFormatter={(value) => shortDay(value)}
        />
        {[...SEVERITIES].reverse().map((severity) => (
          <Area
            key={severity}
            type="monotone"
            dataKey={severity}
            stackId="severity"
            stroke={SEVERITY_COLORS[severity]}
            strokeWidth={1.8}
            fill={`url(#fill-${severity})`}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityDonut({ data = [] }) {
  const total = data.reduce((sum, item) => sum + (item.count || 0), 0);
  const series = data.filter((item) => item.count > 0);

  return (
    <div className="donut-wrap">
      <ResponsiveContainer width="100%" height={230}>
        <PieChart>
          <Pie
            data={series}
            dataKey="count"
            nameKey="severity"
            innerRadius={62}
            outerRadius={92}
            paddingAngle={3}
            stroke="none"
          >
            {series.map((item) => (
              <Cell key={item.severity} fill={SEVERITY_COLORS[item.severity]} />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={ITEM_STYLE} />
        </PieChart>
      </ResponsiveContainer>
      <div className="donut-center">
        <strong>{compactNumber(total)}</strong>
        <span>indicators</span>
      </div>
    </div>
  );
}

export function SourceBars({ data = [] }) {
  const series = data.map((item) => ({ ...item, short: item.source.split("—")[0].trim() }));

  return (
    <ResponsiveContainer width="100%" height={Math.max(220, series.length * 38)}>
      <BarChart data={series} layout="vertical" margin={{ top: 4, right: 18, left: 8, bottom: 4 }} barSize={14}>
        <CartesianGrid stroke="#152134" strokeDasharray="3 6" horizontal={false} />
        <XAxis type="number" tick={AXIS_STYLE} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="short"
          tick={{ ...AXIS_STYLE, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={128}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          itemStyle={ITEM_STYLE}
          labelStyle={LABEL_STYLE}
          formatter={(value, name) => [formatNumber(value), name === "count" ? "Indicators" : "Critical"]}
        />
        <Bar dataKey="count" fill="#2ee6c5" radius={[0, 6, 6, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryBars({ data = [] }) {
  const series = [...data].reverse();

  return (
    <ResponsiveContainer width="100%" height={Math.max(200, series.length * 34)}>
      <BarChart data={series} layout="vertical" margin={{ top: 4, right: 18, left: 8, bottom: 4 }} barSize={12}>
        <CartesianGrid stroke="#152134" strokeDasharray="3 6" horizontal={false} />
        <XAxis type="number" tick={AXIS_STYLE} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="category"
          tick={{ ...AXIS_STYLE, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={132}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={ITEM_STYLE} labelStyle={LABEL_STYLE} />
        <Bar dataKey="count" fill="#4dabf7" radius={[0, 6, 6, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
