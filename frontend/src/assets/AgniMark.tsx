import React from 'react';

interface AgniMarkProps {
  className?: string;
  size?: number;
}

export const AgniMark: React.FC<AgniMarkProps> = ({ className = "w-8 h-8", size }) => {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 48 48" 
      fill="none" 
      className={className}
      style={size ? { width: size, height: size } : undefined}
      aria-label="Agni Fire-Shield Emblem"
    >
      <defs>
        <linearGradient id="agni-mark-flame" x1="12" y1="6" x2="36" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#06b6d4" />
          <stop offset="60%" stopColor="#3b82f6" />
          <stop offset="100%" stopColor="#1d4ed8" />
        </linearGradient>
        <linearGradient id="agni-mark-core" x1="24" y1="18" x2="24" y2="38" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#f59e0b" />
          <stop offset="50%" stopColor="#ef4444" />
          <stop offset="100%" stopColor="#991b1b" />
        </linearGradient>
        <linearGradient id="agni-mark-shield" x1="24" y1="2" x2="24" y2="46" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#1e293b" stopOpacity="0.3" />
        </linearGradient>
      </defs>

      {/* Hexagonal Shield Perimeter */}
      <path 
        d="M24 3L41 10V22C41 33.2 33.7 41.5 24 45C14.3 41.5 7 33.2 7 22V10L24 3Z" 
        stroke="url(#agni-mark-shield)" 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round" 
        fill="#0f172a" 
        fillOpacity="0.85" 
      />

      {/* Outer Geometric Flame Facets */}
      <path 
        d="M24 9C24 9 29 16 29 22C29 25 27 27 25 29C29 27 34 23 34 18C34 28 28 35 24 38C20 35 14 28 14 18C14 23 19 27 23 29C21 27 19 25 19 22C19 16 24 9 24 9Z" 
        fill="url(#agni-mark-flame)" 
      />

      {/* Inner Dynamic Flame Core */}
      <path 
        d="M24 16C24 16 27 21 27 25C27 28.5 24 33 24 33C24 33 21 28.5 21 25C21 21 24 16 24 16Z" 
        fill="url(#agni-mark-core)" 
      />

      {/* Center Radar / Telemetry Pulse Node */}
      <circle cx="24" cy="27" r="2.5" fill="#f8fafc" />
    </svg>
  );
};
