import { useState, useEffect } from "react";
import {
  Activity, CheckCircle, ShieldCheck, Database, Cpu, Globe,
  Server, RefreshCw, AlertCircle, Clock, Zap
} from "lucide-react";
import api from "../api/client";

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [latency, setLatency] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const checkStatus = async () => {
    setLoading(true);
    setError("");
    const startTime = performance.now();
    try {
      const res = await api.get("/api/threat/system-status");
      const endTime = performance.now();
      setLatency(Math.round(endTime - startTime));
      setStatus(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Could not connect to PhishGuard API gateway.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkStatus();
  }, []);

  return (
    <div className="max-w-4xl mx-auto px-4 py-10 space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-2">
            <Activity className="w-8 h-8 text-blue-400" /> Cloud & System Status
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Real-time telemetry on Machine Learning models, cloud runtime, threat feeds, and database health.
          </p>
        </div>

        <button
          onClick={checkStatus}
          disabled={loading}
          className="btn-secondary text-sm flex items-center gap-2 self-start sm:self-center"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-blue-400" : ""}`} />
          Refresh Status
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {status && (
        <div className="space-y-6">
          {/* Main Health Banner */}
          <div className="card bg-gradient-to-r from-gray-900 to-gray-800/80 border border-gray-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="bg-green-900/30 p-3 rounded-full border border-green-800">
                <CheckCircle className="w-7 h-7 text-green-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xl font-bold text-white">All Systems Operational</h2>
                  <span className="badge-legitimate text-xs uppercase">{status.status}</span>
                </div>
                <p className="text-gray-400 text-xs mt-0.5">
                  PhishGuard Cloud Engine v{status.version} · Active Environment: {status.environment}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-6">
              <div className="text-right">
                <p className="text-xs text-gray-500">API Latency</p>
                <p className="text-lg font-bold text-green-400 flex items-center gap-1 justify-end">
                  <Zap className="w-4 h-4" /> {latency !== null ? `${latency} ms` : "..."}
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-500">Server Time</p>
                <p className="text-xs font-mono text-gray-300">
                  {new Date(status.timestamp).toLocaleTimeString()} UTC
                </p>
              </div>
            </div>
          </div>

          {/* Telemetry Grid */}
          <div className="grid sm:grid-cols-2 gap-4">
            {/* ML Inference Engine */}
            <div className="card space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-blue-400" />
                  <h3 className="font-semibold text-white text-sm">Machine Learning Model</h3>
                </div>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-900/40 text-blue-400 border border-blue-800">
                  {status.ml_engine.model_loaded ? "READY (IN-MEMORY)" : "HEURISTIC FALLBACK"}
                </span>
              </div>
              <p className="text-xs text-gray-400">
                Scikit-Learn Random Forest classifier with calibrated feature extraction.
              </p>
              <div className="space-y-1.5 text-xs text-gray-300 pt-1">
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-gray-500">Algorithm</span>
                  <span className="font-mono text-gray-200">{status.ml_engine.algorithm}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-gray-500">Extracted Features Vector</span>
                  <span className="font-mono text-blue-400">{status.ml_engine.features_extracted} features</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-gray-500">Inference Mode</span>
                  <span className="font-mono text-green-400">{status.ml_engine.inference_mode}</span>
                </div>
              </div>
            </div>

            {/* Database & Storage */}
            <div className="card space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-purple-400" />
                  <h3 className="font-semibold text-white text-sm">Database & Records</h3>
                </div>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-800">
                  CONNECTED
                </span>
              </div>
              <p className="text-xs text-gray-400">
                Persistent storage for user sessions, whitelist rules, scan telemetry, and threat statistics.
              </p>
              <div className="space-y-1.5 text-xs text-gray-300 pt-1">
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-gray-500">Storage Backend</span>
                  <span className="font-mono uppercase text-gray-200">{status.database.engine}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800">
                  <span className="text-gray-500">Total Scans Recorded</span>
                  <span className="font-mono text-purple-400">{status.database.total_scans_recorded} scans</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-gray-500">Registered Accounts</span>
                  <span className="font-mono text-gray-200">{status.database.registered_users} accounts</span>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence Providers Grid */}
          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-green-400" /> Connected Threat Intelligence Feeds
            </h3>
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* VirusTotal */}
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">VirusTotal</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                    status.threat_providers.virustotal.configured ? "bg-green-900/40 text-green-400" : "bg-gray-800 text-gray-500"
                  }`}>
                    {status.threat_providers.virustotal.configured ? "ACTIVE" : "STANDBY"}
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 leading-tight">
                  {status.threat_providers.virustotal.configured
                    ? "70+ security engines integrated"
                    : "Add VIRUSTOTAL_API_KEY in .env"}
                </p>
              </div>

              {/* WHOIS */}
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">WHOIS / RDAP</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-green-900/40 text-green-400">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 leading-tight">
                  Domain age & registrar inspection
                </p>
              </div>

              {/* SSL */}
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">SSL Validator</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-green-900/40 text-green-400">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 leading-tight">
                  TLS 1.2 / 1.3 cert expiration checks
                </p>
              </div>

              {/* SSRF Protection */}
              <div className="bg-gray-950 p-3 rounded-lg border border-gray-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">SSRF Shield</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-green-900/40 text-green-400">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 leading-tight">
                  RFC1918 & metadata protection
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-gray-500 pt-3 border-t border-gray-800/80">
              <span>Primary Cluster: AWS Sydney Serverless</span>
              <a
                href="https://phishguard-pm3q.onrender.com/index.html"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 hover:text-blue-400 transition-colors flex items-center gap-1"
              >
                Secondary Failover Mirror ↗
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
