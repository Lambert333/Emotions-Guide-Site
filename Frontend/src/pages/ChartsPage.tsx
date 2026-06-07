import React, { useState, useEffect } from "react";
import { BarChart3, TrendingUp, Calendar, RefreshCw } from "lucide-react";
import { analyticsAPI } from "../services/api";
import {
  ANALYTICS_SOURCE,
  AnalyticsEvents,
  type AnalyticsPeriod,
} from "../shared/analytics/analyticsEvents";
import { trackEvent } from "../shared/analytics/firebaseAnalytics";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ComposedChart,
  Area,
} from "recharts";

interface TestResult {
  resultId: string;
  userId: string;
  wellbeingScore: number;
  activityScore: number;
  moodScore: number;
  timestamp: string;
}

interface ChartData {
  date: string;
  wellbeing: number;
  activity: number;
  mood: number;
}

const ChartsPage: React.FC = () => {
  const [, setTestResults] = useState<TestResult[]>([]);
  const [chartData, setChartData] = useState<ChartData[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<AnalyticsPeriod>("month");
  const [selectedMetric, setSelectedMetric] = useState<
    "wellbeing" | "activity" | "mood" | "all"
  >("all");
  const [stats, setStats] = useState({
    avgWellbeing: 0,
    avgActivity: 0,
    avgMood: 0,
    totalTests: 0,
    trend: "stable" as "improving" | "declining" | "stable",
  });

  useEffect(() => {
    loadTestResults();
  }, [timeRange]);

  useEffect(() => {
    trackEvent(AnalyticsEvents.ANALYTICS_OPENED, {
      source: ANALYTICS_SOURCE,
    });
  }, []);

  const handleTimeRangeChange = (nextRange: AnalyticsPeriod) => {
    if (nextRange !== timeRange) {
      trackEvent(AnalyticsEvents.PERIOD_CHANGED, {
        source: ANALYTICS_SOURCE,
        period: nextRange,
      });
    }

    setTimeRange(nextRange);
  };

  const loadTestResults = async () => {
    try {
      let limit = 30;
      if (timeRange === "week") limit = 7;
      if (timeRange === "month") limit = 30;

      const results = await analyticsAPI.getTestStatistics(limit);
      setTestResults(results);
      processChartData(results);
      calculateStats(results);
    } catch (error) {
      console.error("Error loading test results:", error);
    } finally {
      setLoading(false);
    }
  };

  const processChartData = (results: TestResult[]) => {
    const data: ChartData[] = results
      .map((result) => ({
        date: new Date(result.timestamp).toLocaleDateString("ru-RU", {
          day: "2-digit",
          month: "short",
        }),
        wellbeing: Math.round(result.wellbeingScore * 10) / 10,
        activity: Math.round(result.activityScore * 10) / 10,
        mood: Math.round(result.moodScore * 10) / 10,
        fullDate: new Date(result.timestamp).toLocaleDateString("ru-RU", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
        }),
      }))
      .reverse(); // Reverse to show chronological order

    setChartData(data);
  };

  const calculateStats = (results: TestResult[]) => {
    if (results.length === 0) return;

    const wellbeingSum = results.reduce((sum, r) => sum + r.wellbeingScore, 0);
    const activitySum = results.reduce((sum, r) => sum + r.activityScore, 0);
    const moodSum = results.reduce((sum, r) => sum + r.moodScore, 0);
    const total = results.length;

    // Calculate trend (simplified)
    const firstHalf = results.slice(0, Math.floor(total / 2));
    const secondHalf = results.slice(Math.floor(total / 2));

    const firstAvg =
      firstHalf.reduce(
        (sum, r) => sum + r.wellbeingScore + r.activityScore + r.moodScore,
        0
      ) /
      (firstHalf.length * 3);
    const secondAvg =
      secondHalf.reduce(
        (sum, r) => sum + r.wellbeingScore + r.activityScore + r.moodScore,
        0
      ) /
      (secondHalf.length * 3);

    let trend: "improving" | "declining" | "stable" = "stable";
    if (secondAvg > firstAvg + 0.5) trend = "improving";
    else if (secondAvg < firstAvg - 0.5) trend = "declining";

    setStats({
      avgWellbeing: Math.round((wellbeingSum / total) * 10) / 10,
      avgActivity: Math.round((activitySum / total) * 10) / 10,
      avgMood: Math.round((moodSum / total) * 10) / 10,
      totalTests: total,
      trend,
    });
  };

  const getTrendIcon = () => {
    switch (stats.trend) {
      case "improving":
        return "↗️";
      case "declining":
        return "↘️";
      default:
        return "→";
    }
  };

  const getTrendColor = () => {
    switch (stats.trend) {
      case "improving":
        return "var(--positive-color)";
      case "declining":
        return "var(--negative-color)";
      default:
        return "var(--hint-color)";
    }
  };

  const getTrendText = () => {
    switch (stats.trend) {
      case "improving":
        return "Улучшение";
      case "declining":
        return "Снижение";
      default:
        return "Стабильно";
    }
  };

  const renderChart = () => {
    if (chartData.length === 0) {
      return (
        <div
          style={{
            height: "300px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--hint-color)",
            fontSize: "16px",
          }}
        >
          Нет данных для отображения
        </div>
      );
    }

    const chartHeight = 300;
    const margin = { top: 20, right: 30, left: 20, bottom: 30 };

    if (selectedMetric === "all") {
      return (
        <ResponsiveContainer width="100%" height={chartHeight}>
          <ComposedChart data={chartData} margin={margin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 10 }}
              angle={-45}
              textAnchor="end"
              height={60}
            />
            <YAxis domain={[0, 7]} tickCount={8} tick={{ fontSize: 10 }} />
            <Tooltip
              formatter={(value: number) => [value.toFixed(1), "Балл"]}
              contentStyle={{
                backgroundColor: "var(--card-background)",
                border: "1px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="wellbeing"
              fill="rgba(76, 175, 80, 0.1)"
              stroke="var(--positive-color)"
              strokeWidth={2}
              name="Самочувствие"
            />
            <Area
              type="monotone"
              dataKey="activity"
              fill="rgba(0, 102, 255, 0.1)"
              stroke="var(--primary-blue)"
              strokeWidth={2}
              name="Активность"
            />
            <Area
              type="monotone"
              dataKey="mood"
              fill="rgba(255, 152, 0, 0.1)"
              stroke="var(--warning-color)"
              strokeWidth={2}
              name="Настроение"
            />
          </ComposedChart>
        </ResponsiveContainer>
      );
    } else {
      return (
        <ResponsiveContainer width="100%" height={chartHeight}>
          <BarChart data={chartData} margin={margin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 10 }}
              angle={-45}
              textAnchor="end"
              height={60}
            />
            <YAxis domain={[0, 7]} tickCount={8} tick={{ fontSize: 10 }} />
            <Tooltip
              formatter={(value: number) => [value.toFixed(1), "Балл"]}
              contentStyle={{
                backgroundColor: "var(--card-background)",
                border: "1px solid #e0e0e0",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            />
            <Legend />
            <Bar
              dataKey={selectedMetric}
              fill={
                selectedMetric === "wellbeing"
                  ? "var(--positive-color)"
                  : selectedMetric === "activity"
                  ? "var(--primary-blue)"
                  : "var(--warning-color)"
              }
              name={
                selectedMetric === "wellbeing"
                  ? "Самочувствие"
                  : selectedMetric === "activity"
                  ? "Активность"
                  : "Настроение"
              }
              radius={[4, 4, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      );
    }
  };

  const renderMetricTabs = () => (
    <div className="metric-tabs-container">
      {[
        { value: "all", label: "Все", color: "var(--primary-blue)" },
        {
          value: "wellbeing",
          label: "Самочувствие",
          color: "var(--positive-color)",
        },
        {
          value: "activity",
          label: "Активность",
          color: "var(--primary-blue)",
        },
        { value: "mood", label: "Настроение", color: "var(--warning-color)" },
      ].map(({ value, label, color }) => (
        <button
          key={value}
          className="metric-tab-button"
          onClick={() => setSelectedMetric(value as any)}
          style={{
            border: `1px solid ${selectedMetric === value ? color : "#e0e0e0"}`,
            backgroundColor: selectedMetric === value ? color : "transparent",
            color: selectedMetric === value ? "white" : "var(--text-color)",
          }}
        >
          {label}
        </button>
      ))}
    </div>
  );

  const renderTimeRangeFilter = () => (
    <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
      {([
        { value: "week", label: "Неделя" },
        { value: "month", label: "Месяц" },
        { value: "all", label: "Все время" },
      ] as Array<{ value: AnalyticsPeriod; label: string }>).map(({ value, label }) => (
        <button
          key={value}
          onClick={() => handleTimeRangeChange(value)}
          style={{
            padding: "8px 12px",
            border: `1px solid ${
              timeRange === value ? "var(--primary-blue)" : "#e0e0e0"
            }`,
            borderRadius: "20px",
            backgroundColor:
              timeRange === value ? "var(--primary-blue)" : "transparent",
            color: timeRange === value ? "white" : "var(--text-color)",
            fontSize: "12px",
            cursor: "pointer",
          }}
        >
          {label}
        </button>
      ))}
    </div>
  );

  if (loading) {
    return (
      <div className="container">
        <div className="card text-center">
          <h2>Загрузка данных...</h2>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card text-center mb-8">
        <h2
          className="mb-4"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
          }}
        >
          <BarChart3 size={24} />
          Графики и динамика
        </h2>
        <p>Смотрите динамику ваших отметок</p>
      </div>

      <div className="card mb-8">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
          }}
        >
          <h3
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              margin: 0,
            }}
          >
            <TrendingUp size={20} />
            Динамика теста САН
          </h3>
          <button
            className="btn"
            onClick={loadTestResults}
            style={{ padding: "8px 12px", fontSize: "12px" }}
          >
            <RefreshCw size={14} style={{ marginRight: "4px" }} />
            Обновить
          </button>
        </div>

        {renderTimeRangeFilter()}
        {renderMetricTabs()}

        {renderChart()}
      </div>

      <div className="card mb-8">
        <h3
          className="mb-4"
          style={{ display: "flex", alignItems: "center", gap: "8px" }}
        >
          <Calendar size={20} />
          Статистика
        </h3>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
            gap: "16px",
          }}
        >
          <div
            style={{
              textAlign: "center",
              padding: "16px",
              backgroundColor: "rgba(0, 102, 255, 0.1)",
              borderRadius: "8px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                marginBottom: "8px",
                fontWeight: "bold",
              }}
            >
              Тестов
            </div>
            <div
              style={{
                fontSize: "24px",
                fontWeight: "bold",
                color: "var(--primary-blue)",
              }}
            >
              {stats.totalTests}
            </div>
          </div>

          <div
            style={{
              textAlign: "center",
              padding: "16px",
              backgroundColor: "rgba(76, 175, 80, 0.1)",
              borderRadius: "8px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                marginBottom: "8px",
                fontWeight: "bold",
              }}
            >
              Самочувствие
            </div>
            <div
              style={{
                fontSize: "24px",
                fontWeight: "bold",
                color: "var(--positive-color)",
              }}
            >
              {stats.avgWellbeing}
            </div>
          </div>

          <div
            style={{
              textAlign: "center",
              padding: "16px",
              backgroundColor: "rgba(0, 102, 255, 0.1)",
              borderRadius: "8px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                marginBottom: "8px",
                fontWeight: "bold",
              }}
            >
              Активность
            </div>
            <div
              style={{
                fontSize: "24px",
                fontWeight: "bold",
                color: "var(--primary-blue)",
              }}
            >
              {stats.avgActivity}
            </div>
          </div>

          <div
            style={{
              textAlign: "center",
              padding: "16px",
              backgroundColor: "rgba(255, 152, 0, 0.1)",
              borderRadius: "8px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                marginBottom: "8px",
                fontWeight: "bold",
              }}
            >
              Настроение
            </div>
            <div
              style={{
                fontSize: "24px",
                fontWeight: "bold",
                color: "var(--warning-color)",
              }}
            >
              {stats.avgMood}
            </div>
          </div>

          <div
            style={{
              textAlign: "center",
              padding: "16px",
              backgroundColor: "rgba(158, 158, 158, 0.1)",
              borderRadius: "8px",
            }}
          >
            <div
              style={{
                fontSize: "14px",
                marginBottom: "8px",
                fontWeight: "bold",
              }}
            >
              Тренд
            </div>
            <div
              style={{
                fontSize: "24px",
                fontWeight: "bold",
                color: getTrendColor(),
              }}
            >
              {getTrendIcon()}
            </div>
            <div style={{ fontSize: "12px", color: getTrendColor() }}>
              {getTrendText()}
            </div>
          </div>
        </div>
      </div>
</div>
);
};

export default ChartsPage;
