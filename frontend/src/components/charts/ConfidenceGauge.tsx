'use client';

interface ConfidenceGaugeProps {
  value: number; // 0-100
  size?: number;
}

export function ConfidenceGauge({ value, size = 150 }: ConfidenceGaugeProps) {
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  
  const getColor = (val: number) => {
    if (val >= 80) return '#10b981'; // green
    if (val >= 60) return '#3b82f6'; // blue
    if (val >= 40) return '#eab308'; // yellow
    return '#ef4444'; // red
  };

  return (
    <div className="flex flex-col items-center justify-center">
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#374151"
          strokeWidth="12"
          fill="none"
        />
        {/* Value circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={getColor(value)}
          strokeWidth="12"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-300"
        />
      </svg>
      <div className="absolute text-center" style={{ marginTop: -size / 2 }}>
        <div className="text-3xl font-bold" style={{ color: getColor(value) }}>
          {value.toFixed(0)}%
        </div>
        <div className="text-sm text-gray-400">Confidence</div>
      </div>
    </div>
  );
}

