import React from 'react';
import { useApp } from '../context/AppContext';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useApp();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none">
      {toasts.map(t => {
        let icon = <Info className="w-5 h-5 text-cyan-400" />;
        let borderClass = 'border-cyan-500/40 bg-slate-900/95';

        if (t.type === 'success') {
          icon = <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
          borderClass = 'border-emerald-500/40 bg-slate-900/95';
        } else if (t.type === 'warning') {
          icon = <AlertTriangle className="w-5 h-5 text-amber-400" />;
          borderClass = 'border-amber-500/40 bg-slate-900/95';
        } else if (t.type === 'error') {
          icon = <AlertCircle className="w-5 h-5 text-rose-400" />;
          borderClass = 'border-rose-500/40 bg-slate-900/95';
        }

        return (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start gap-3 p-4 rounded-lg border shadow-xl backdrop-blur-md transition-all animate-slideUp ${borderClass}`}
          >
            <div className="flex-shrink-0 mt-0.5">{icon}</div>
            <div className="flex-1 text-sm text-slate-200">{t.message}</div>
            <button
              onClick={() => removeToast(t.id)}
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
