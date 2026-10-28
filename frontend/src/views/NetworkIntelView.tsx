import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { InterfaceRead, NetworkDeviceRead, SocketRead } from '../types/api';
import {
  Network,
  Radio,
  Search,
  ShieldCheck,
  Laptop,
  Wifi,
  RefreshCw,
} from 'lucide-react';

export const NetworkIntelView: React.FC = () => {
  const { refreshTrigger } = useApp();
  const [interfaces, setInterfaces] = useState<InterfaceRead[]>([]);
  const [sockets, setSockets] = useState<SocketRead[]>([]);
  const [devices, setDevices] = useState<NetworkDeviceRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [socketFilter, setSocketFilter] = useState<'ALL' | 'LISTEN' | 'ESTABLISHED'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    Promise.all([
      api.getNetworkInterfaces(),
      api.getNetworkConnections(500),
      api.getNetworkDevices(true),
    ])
      .then(([ifaces, socks, devs]) => {
        setInterfaces(ifaces);
        setSockets(socks);
        setDevices(devs);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [refreshTrigger]);

  const filteredSockets = sockets.filter(s => {
    if (socketFilter !== 'ALL' && s.status !== socketFilter) {
      return false;
    }
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchProc = (s.process_name || '').toLowerCase().includes(q);
      const matchLocal = `${s.local_address}:${s.local_port}`.includes(q);
      const matchRemote = `${s.remote_address || ''}:${s.remote_port || ''}`.includes(q);
      const matchPid = String(s.pid).includes(q);
      return matchProc || matchLocal || matchRemote || matchPid;
    }
    return true;
  });

  if (loading && interfaces.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Network Interfaces & Socket Telemetry...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Defensive Policy Scope Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-start gap-3 shadow-md">
        <ShieldCheck className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <div className="font-semibold text-slate-200">
            Vayu Network Defensive Scope Policy
          </div>
          <p className="text-slate-400 leading-relaxed">
            Authorized local network interface inventory and active socket mapping only. In accordance with platform safety principles, stealth port scanning, packet payload interception, and unauthorized external subnet probing are strictly disabled.
          </p>
        </div>
      </div>

      {/* Network Interface Cards */}
      <div>
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Wifi className="w-4 h-4 text-cyan-400" /> Host Network Adapters
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {interfaces.map(iface => (
            <div
              key={iface.name}
              className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-sm space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-sm text-slate-200 flex items-center gap-2">
                  <Laptop className="w-4 h-4 text-cyan-400" /> {iface.name}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                    iface.is_up
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {iface.is_up ? 'ACTIVE (UP)' : 'DOWN'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800/80">
                <div>
                  <span className="text-slate-500">IPv4 Address: </span>
                  <span className="text-cyan-300">{iface.ipv4_addresses?.[0] || 'Unassigned'}</span>
                </div>
                <div>
                  <span className="text-slate-500">MAC Address: </span>
                  <span className="text-slate-300">{iface.mac_address || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Netmask: </span>
                  <span className="text-slate-400">{iface.netmask || '255.255.255.0'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Link Speed: </span>
                  <span className="text-slate-400">{iface.speed_mbps ? `${iface.speed_mbps} Mbps` : 'Virtual'}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Active Socket Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" /> Active TCP/UDP Sockets ({filteredSockets.length})
            </h3>

            {/* Socket State Filter */}
            <div className="flex items-center bg-slate-900 border border-slate-700 rounded-lg p-1 text-xs">
              <button
                onClick={() => setSocketFilter('ALL')}
                className={`px-2.5 py-1 rounded transition ${
                  socketFilter === 'ALL' ? 'bg-cyan-600/30 text-cyan-300 font-semibold' : 'text-slate-400'
                }`}
              >
                All States
              </button>
              <button
                onClick={() => setSocketFilter('LISTEN')}
                className={`px-2.5 py-1 rounded transition ${
                  socketFilter === 'LISTEN' ? 'bg-cyan-600/30 text-cyan-300 font-semibold' : 'text-slate-400'
                }`}
              >
                LISTEN
              </button>
              <button
                onClick={() => setSocketFilter('ESTABLISHED')}
                className={`px-2.5 py-1 rounded transition ${
                  socketFilter === 'ESTABLISHED' ? 'bg-cyan-600/30 text-cyan-300 font-semibold' : 'text-slate-400'
                }`}
              >
                ESTABLISHED
              </button>
            </div>
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search IP, port, process..."
              className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Local Endpoint</th>
                <th className="py-2.5 px-3">Remote Endpoint</th>
                <th className="py-2.5 px-3">State</th>
                <th className="py-2.5 px-4 font-sans">Owner Process</th>
                <th className="py-2.5 px-3">PID</th>
                <th className="py-2.5 px-3">Scope</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredSockets.map((s, idx) => {
                const isOut = s.is_outbound;
                const isRemoteSus = s.remote_port === 4444;
                return (
                  <tr
                    key={idx}
                    className={`hover:bg-slate-800/50 transition ${isRemoteSus ? 'bg-rose-950/20' : ''}`}
                  >
                    <td className="py-2 px-3 text-cyan-400 font-bold">{s.protocol}</td>
                    <td className="py-2 px-3">{s.local_address}:{s.local_port}</td>
                    <td className={`py-2 px-3 ${isRemoteSus ? 'text-rose-400 font-bold' : 'text-slate-300'}`}>
                      {s.remote_address ? `${s.remote_address}:${s.remote_port}` : '*:*'}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] ${
                          s.status === 'LISTEN'
                            ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
                            : s.status === 'ESTABLISHED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {s.status || 'CONNECTED'}
                      </span>
                    </td>
                    <td className="py-2 px-4 font-sans font-medium text-slate-200">
                      {s.process_name || 'System / Unresolved'}
                    </td>
                    <td className="py-2 px-3 text-slate-400">{s.pid}</td>
                    <td className="py-2 px-3 font-sans">
                      {s.local_address.startsWith('127.') || s.local_address === '::1' ? (
                        <span className="text-[10px] text-slate-500">Loopback</span>
                      ) : isOut ? (
                        <span className="text-[10px] text-amber-400 font-mono">WAN Outbound</span>
                      ) : (
                        <span className="text-[10px] text-slate-400">LAN Svc</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Discovered Subnet Devices (ARP Table) */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg p-4 space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400" /> Authorized Subnet Devices (Passive ARP Cache)
        </h3>

        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">IP Address</th>
                <th className="py-2.5 px-3">MAC Hardware Address</th>
                <th className="py-2.5 px-4 font-sans">Vendor / Hostname</th>
                <th className="py-2.5 px-3">First Seen</th>
                <th className="py-2.5 px-3">Last Seen</th>
                <th className="py-2.5 px-3 text-right">Gateway</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {devices.map(d => (
                <tr key={d.id} className="hover:bg-slate-800/50 transition">
                  <td className="py-2 px-3 text-cyan-300 font-bold">{d.ip_address}</td>
                  <td className="py-2 px-3 text-slate-400">{d.mac_address || 'N/A'}</td>
                  <td className="py-2 px-4 font-sans text-slate-200">
                    {d.vendor || d.hostname || 'Local Network Node'}
                  </td>
                  <td className="py-2 px-3 text-slate-500 text-[11px]">
                    {new Date(d.first_seen).toLocaleDateString()}
                  </td>
                  <td className="py-2 px-3 text-slate-400 text-[11px]">
                    {new Date(d.last_seen).toLocaleTimeString()}
                  </td>
                  <td className="py-2 px-3 text-right">
                    {d.is_gateway ? (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-sans font-semibold">
                        Default Gateway
                      </span>
                    ) : (
                      <span className="text-slate-600 text-[11px]">Host</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
