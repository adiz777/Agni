import React from 'react';
import { AgniMark } from './AgniMark';

interface AgniLogoProps {
  className?: string;
  markSize?: number;
  showSubtitle?: boolean;
}

export const AgniLogo: React.FC<AgniLogoProps> = ({
  className = "flex items-center gap-3",
  markSize = 36,
  showSubtitle = true,
}) => {
  return (
    <div className={className} aria-label="Agni Threat Monitoring Platform">
      <AgniMark size={markSize} className="flex-shrink-0" />
      <div className="flex flex-col">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold tracking-wider text-slate-50 uppercase font-mono">
            AGNI
          </span>
          <span className="text-sm font-semibold text-cyan-400 bg-cyan-950/70 border border-cyan-800/50 px-1.5 py-0.5 rounded text-xs">
            अग्नि
          </span>
        </div>
        {showSubtitle && (
          <span className="text-[10px] font-medium tracking-[0.18em] text-slate-400 uppercase">
            Threat Detection &amp; SOC
          </span>
        )}
      </div>
    </div>
  );
};
