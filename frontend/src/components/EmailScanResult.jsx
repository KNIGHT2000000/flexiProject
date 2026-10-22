import React from "react";
import {
  Mail, AlertTriangle, ShieldAlert, ShieldCheck, ShieldX,
  ExternalLink, UserX, UserCheck, AlertCircle, ArrowRight
} from "lucide-react";
import RiskMeter from "./RiskMeter";

export default function EmailScanResult({ result }) {
  if (!result) return null;

  const {
    urls_found = 0,
    results = [],
    email_risk_score = 0.0,
    email_prediction = "legitimate",
    lures_detected = [],
    sender = {},
    mismatched_links = [],
    recommendations = [],
  } = result;

  const isPhishing = email_prediction === "phishing" || email_risk_score >= 60;
  const isSuspicious = email_prediction === "suspicious" || (email_risk_score >= 30 && email_risk_score < 60);

  const badgeColor = isPhishing
    ? "bg-red-900/40 text-red-400 border-red-800"
    : isSuspicious
    ? "bg-yellow-900/40 text-yellow-400 border-yellow-800"
    : "bg-green-900/40 text-green-400 border-green-800";

  return (
    <div className="mt-8 space-y-6">
      {/* Top Banner Verdict */}
      <div className={`card border-l-4 ${isPhishing ? "border-l-red-500" : isSuspicious ? "border-l-yellow-500" : "border-l-green-500"} flex flex-col md:flex-row items-center justify-between gap-6`}>
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            {isPhishing ? (
              <ShieldX className="w-8 h-8 text-red-400" />
            ) : isSuspicious ? (
              <ShieldAlert className="w-8 h-8 text-yellow-400" />
            ) : (
              <ShieldCheck className="w-8 h-8 text-green-400" />
            )}
            <div>
              <span className={`text-xs uppercase font-bold tracking-wider px-2.5 py-0.5 rounded-full border ${badgeColor}`}>
                {email_prediction}
              </span>
              <h2 className="text-xl font-bold text-white mt-1">
                {isPhishing
                  ? "High-Risk Phishing Email Detected"
                  : isSuspicious
                  ? "Suspicious Email Indicators Found"
                  : "Email Appears Legitimate"}
              </h2>
            </div>
          </div>
          <p className="text-gray-400 text-sm">
            {isPhishing
              ? "This email exhibits deceptive social engineering tactics and contains malicious elements."
              : isSuspicious
              ? "Exercise caution. Review the sender identity and embedded URLs carefully."
              : "No high-risk phishing lures or malicious links detected in the analyzed text."}
          </p>
        </div>

        <div className="flex-shrink-0">
          <RiskMeter score={email_risk_score} />
        </div>
      </div>

      {/* Sender Spoofing & Authenticity Card */}
      {sender && (sender.display_name || sender.email_address) && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
            {sender.is_spoofed ? (
              <UserX className="w-4 h-4 text-red-400" />
            ) : (
              <UserCheck className="w-4 h-4 text-green-400" />
            )}
            Sender Authenticity & Domain Alignment
          </h3>
          <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="text-gray-400">Display Name:</span>
              <span className="text-white font-medium">{sender.display_name || "N/A"}</span>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="text-gray-400">From Address:</span>
              <span className="text-blue-300 font-mono text-xs">{sender.email_address || "N/A"}</span>
            </div>
            {sender.reply_to && (
              <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="text-gray-400">Reply-To Address:</span>
                <span className="text-orange-300 font-mono text-xs">{sender.reply_to}</span>
              </div>
            )}
            {sender.is_spoofed && (
              <div className="mt-2 text-xs text-red-400 bg-red-950/40 border border-red-800 p-2.5 rounded-md flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                <span><strong>Sender Spoofing Warning:</strong> {sender.spoof_reason}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Social Engineering / Psychological Lures */}
      {lures_detected && lures_detected.length > 0 && (
        <div className="card border-l-4 border-l-orange-500">
          <h3 className="text-sm font-semibold text-orange-400 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Psychological & Urgency Lures Detected ({lures_detected.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {lures_detected.map((l, i) => (
              <div
                key={i}
                className="bg-orange-950/40 border border-orange-800/80 px-3 py-1.5 rounded-lg text-xs text-orange-300 flex items-center gap-2"
              >
                <span className="w-2 h-2 rounded-full bg-orange-400"></span>
                <span className="font-semibold">{l.lure}</span>
                {l.matched_text && (
                  <span className="text-gray-400 italic">("{l.matched_text}")</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Mismatched Anchor Links Warning */}
      {mismatched_links && mismatched_links.length > 0 && (
        <div className="card border-l-4 border-l-red-500">
          <h3 className="text-sm font-semibold text-red-400 mb-3 flex items-center gap-2">
            <AlertCircle className="w-4 h-4" /> Deceptive Hyperlinks (Mismatched Anchor Text)
          </h3>
          <div className="space-y-2">
            {mismatched_links.map((m, i) => (
              <div key={i} className="bg-red-950/30 border border-red-800/60 p-3 rounded-lg text-xs space-y-1">
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="text-gray-500">Visible Text:</span>
                  <span className="text-yellow-300 font-semibold">{m.display_text}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="text-gray-500">Actual Destination:</span>
                  <span className="text-red-400 font-mono break-all">{m.destination_url}</span>
                </div>
                <p className="text-red-400/80 text-[11px] pt-1">{m.reason}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Discovered URLs Breakdown */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <ExternalLink className="w-4 h-4 text-blue-400" /> Embedded URLs Inspected ({urls_found})
          </span>
          <span className="text-xs text-gray-500">ML + Threat Intel Shield</span>
        </h3>

        {results.length === 0 ? (
          <p className="text-gray-500 text-xs py-3 text-center">No URLs detected in the email text.</p>
        ) : (
          <div className="space-y-3">
            {results.map((r, i) => {
              const isPhish = r.prediction === "phishing" || r.risk_score >= 60;
              const isSusp = r.prediction === "suspicious" || (r.risk_score >= 30 && r.risk_score < 60);
              const pillCls = isPhish
                ? "bg-red-900/40 text-red-400 border-red-800"
                : isSusp
                ? "bg-yellow-900/40 text-yellow-400 border-yellow-800"
                : "bg-green-900/40 text-green-400 border-green-800";

              return (
                <div
                  key={i}
                  className="bg-gray-900/60 border border-gray-800 p-3.5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${pillCls} uppercase`}>
                        {r.prediction}
                      </span>
                      <span className="text-xs text-gray-400 font-mono">
                        Risk Score: <strong className="text-white">{r.risk_score}%</strong>
                      </span>
                    </div>
                    <p className="text-sm text-gray-200 font-mono break-all">{r.url}</p>
                    {r.recommendations && r.recommendations.length > 0 && (
                      <p className="text-xs text-gray-400 line-clamp-1">{r.recommendations[0]}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Security Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-blue-400" /> Security Recommendations
          </h3>
          <ul className="space-y-2">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 flex-shrink-0"></span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
