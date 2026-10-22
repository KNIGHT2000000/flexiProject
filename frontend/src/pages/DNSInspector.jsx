import { useState } from "react";
import {
  Globe, Shield, AlertTriangle, CheckCircle, XCircle,
  Search, Loader2, Mail, Server, Info, ShieldCheck, ShieldAlert
} from "lucide-react";
import api from "../api/client";

export default function DNSInspector() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleInspect = async (e) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await api.get(`/api/threat/dns-inspect?domain=${encodeURIComponent(domain.trim())}`);
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "DNS inspection failed. Ensure domain format is valid.");
    } finally {
      setLoading(false);
    }
  };

  const setSample = (sampleDomain) => {
    setDomain(sampleDomain);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-10 space-y-6">
      <div className="text-center mb-8">
        <div className="flex justify-center mb-4">
          <div className="bg-purple-900/30 p-4 rounded-full border border-purple-800">
            <Globe className="w-10 h-10 text-purple-400" />
          </div>
        </div>
        <h1 className="text-3xl font-bold text-white mb-2">DNS Threat & Spoofing Inspector</h1>
        <p className="text-gray-400 text-sm max-w-lg mx-auto">
          Audit any domain's mail exchangers, SPF authentication, DMARC spoofing defense, and DNS infrastructure security.
        </p>
      </div>

      {/* Domain Input Form */}
      <div className="card space-y-3">
        <form onSubmit={handleInspect} className="flex gap-2">
          <input
            className="input text-sm"
            placeholder="Enter domain (e.g. google.com, paypal.com, or test-domain.xyz)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <button
            type="submit"
            className="btn-primary flex items-center gap-2 whitespace-nowrap"
            disabled={loading || !domain.trim()}
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Inspect DNS
          </button>
        </form>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-gray-500">Quick domains:</span>
          {[
            "google.com",
            "microsoft.com",
            "paypal.com",
            "bankofamerica.com",
          ].map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => setSample(d)}
              className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-2.5 py-1 rounded transition-colors"
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Header Score Card */}
          <div className="card flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              {result.security_score >= 80 ? (
                <ShieldCheck className="w-8 h-8 text-green-400" />
              ) : result.security_score >= 50 ? (
                <Shield className="w-8 h-8 text-yellow-400" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-red-400" />
              )}
              <div>
                <h2 className="text-xl font-bold text-white">{result.domain}</h2>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold ${
                    result.risk_level === "LOW" ? "bg-green-900/40 text-green-400 border border-green-800" :
                    result.risk_level === "MEDIUM" ? "bg-yellow-900/40 text-yellow-400 border border-yellow-800" :
                    "bg-red-900/40 text-red-400 border border-red-800"
                  }`}>
                    {result.risk_level} SPOOFING RISK
                  </span>
                  <span className="text-xs text-gray-400">DNS Security Rating</span>
                </div>
              </div>
            </div>

            <div className="text-right">
              <span className={`text-3xl font-extrabold ${
                result.security_score >= 80 ? "text-green-400" :
                result.security_score >= 50 ? "text-yellow-400" :
                "text-red-400"
              }`}>
                {result.security_score}
              </span>
              <span className="text-gray-500 text-sm"> / 100</span>
              <p className="text-xs text-gray-500">Defense Posture</p>
            </div>
          </div>

          {/* Email Authentication Security Grid */}
          <div className="grid sm:grid-cols-2 gap-4">
            {/* SPF Card */}
            <div className="card space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-blue-400" />
                  <h3 className="font-semibold text-sm text-white">SPF (Sender Policy Framework)</h3>
                </div>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                  result.spf_status === "strict" ? "bg-green-900/40 text-green-400" :
                  result.spf_status === "softfail" ? "bg-yellow-900/40 text-yellow-400" :
                  "bg-red-900/40 text-red-400"
                }`}>
                  {result.spf_status.toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-gray-400">
                Authorizes mail servers permitted to send email on behalf of {result.domain}.
              </p>
              <div className="bg-gray-950 p-2.5 rounded border border-gray-800 font-mono text-xs text-gray-300 break-all">
                {result.spf_record || "No SPF record found (Vulnerable to spoofed senders)"}
              </div>
            </div>

            {/* DMARC Card */}
            <div className="card space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <h3 className="font-semibold text-sm text-white">DMARC Policy Enforcement</h3>
                </div>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                  result.dmarc_policy === "reject" ? "bg-green-900/40 text-green-400" :
                  result.dmarc_policy === "quarantine" ? "bg-yellow-900/40 text-yellow-400" :
                  "bg-red-900/40 text-red-400"
                }`}>
                  {result.dmarc_policy ? `p=${result.dmarc_policy}` : "MISSING"}
                </span>
              </div>
              <p className="text-xs text-gray-400">
                Instructs receiving email gateways how to handle unauthorized emails mimicking this domain.
              </p>
              <div className="bg-gray-950 p-2.5 rounded border border-gray-800 font-mono text-xs text-gray-300 break-all">
                {result.dmarc_record || "No DMARC record found (No anti-spoofing enforcement)"}
              </div>
            </div>
          </div>

          {/* Recommendations & Findings */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="card space-y-3">
              <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                <Info className="w-4 h-4 text-blue-400" /> Findings
              </h3>
              <ul className="space-y-1.5 text-xs text-gray-400">
                {result.findings?.map((f, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-blue-500 mt-0.5">•</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="card space-y-3">
              <h3 className="text-sm font-semibold text-yellow-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-500" /> Recommendations
              </h3>
              <ul className="space-y-1.5 text-xs text-gray-300">
                {result.recommendations?.length ? (
                  result.recommendations.map((r, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-yellow-500 mt-0.5">→</span>
                      <span>{r}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-green-400">✓ Excellent DNS security posture. No remedial action needed.</li>
                )}
              </ul>
            </div>
          </div>

          {/* Infrastructure Routing Details */}
          <div className="grid sm:grid-cols-3 gap-4">
            {/* MX Records */}
            <div className="card space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-300">
                <Mail className="w-4 h-4 text-cyan-400" /> Mail Exchangers (MX)
              </div>
              {result.mail_servers?.length ? (
                <div className="space-y-1">
                  {result.mail_servers.map((mx, i) => (
                    <div key={i} className="flex justify-between items-center text-xs bg-gray-950 p-1.5 rounded">
                      <span className="text-gray-300 truncate max-w-[70%]">{mx.exchange}</span>
                      <span className="text-gray-500 font-mono">Prio {mx.preference}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-500">No MX records found</p>
              )}
            </div>

            {/* IP Addresses */}
            <div className="card space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-300">
                <Server className="w-4 h-4 text-teal-400" /> Resolved IP Addresses
              </div>
              <div className="space-y-1">
                {result.ip_addresses?.map((ip, i) => (
                  <div key={i} className="text-xs font-mono text-gray-300 bg-gray-950 p-1.5 rounded">
                    IPv4: {ip}
                  </div>
                ))}
                {result.ipv6_addresses?.map((ip, i) => (
                  <div key={i} className="text-xs font-mono text-gray-400 bg-gray-950 p-1.5 rounded truncate">
                    IPv6: {ip}
                  </div>
                ))}
                {!result.ip_addresses?.length && !result.ipv6_addresses?.length && (
                  <p className="text-xs text-gray-500">No IP records resolved</p>
                )}
              </div>
            </div>

            {/* Nameservers */}
            <div className="card space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-300">
                <Globe className="w-4 h-4 text-purple-400" /> Nameservers (NS)
              </div>
              {result.nameservers?.length ? (
                <div className="space-y-1">
                  {result.nameservers.map((ns, i) => (
                    <div key={i} className="text-xs text-gray-300 bg-gray-950 p-1.5 rounded truncate">
                      {ns}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-500">No NS records resolved</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
