import React from 'react';
import { Severity } from '../types/api';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  className = '',
}) => {
  const norm = (severity || 'informational').toLowerCase();

  let colorClasses = 'bg-sky-500/10 text-sky-400 border-sky-500/30';
  let dotColor = 'bg-sky-400';

  if (norm === 'critical') {
    colorClasses = 'bg-rose-500/15 text-rose-400 border-rose-500/40 animate-pulse';
    dotColor = 'bg-rose-500';
  } else if (norm === 'high') {
    colorClasses = 'bg-orange-500/15 text-orange-400 border-orange-500/40';
    dotColor = 'bg-orange-400';
  } else if (norm === 'medium') {
    colorClasses = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    dotColor = 'bg-amber-400';
  } else if (norm === 'low') {
    colorClasses = 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
    dotColor = 'bg-indigo-400';
  }

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3 py-1.5 gap-2',
  }[size];

  return (
    <span
      className={`inline-flex items-center font-medium font-mono uppercase tracking-wider rounded border ${colorClasses} ${sizeClasses} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {severity}
    </span>
  );
};
