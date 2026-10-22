import { useState } from "react";
import { Mail, Loader2 } from "lucide-react";
import api from "../api/client";
import EmailScanResult from "../components/EmailScanResult";

const SAMPLE = `From: "PayPal Account Security" <support@paypa1-security.com>
Reply-To: security-alerts@attacker-relay.net
Subject: URGENT: Your PayPal Account Has Been Suspended Within 24 Hours

Dear Valued Customer,

We detected multiple unauthorized login attempts from a suspicious device in Moscow, Russia.
For your safety, your account access has been restricted.

You must verify your credentials immediately to avoid permanent account termination:
https://paypal-security-update.com/verify?id=99281

Visit our official help center: <a href="http://malicious-login-trap.xyz/login">https://www.paypal.com</a>

Thank you,
PayPal Security & Risk Management Department`;

export default function EmailAnalyzer() {
  const [headers, setHeaders] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyze = async () => {
    if (!headers.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await api.post("/api/scan/email", { headers });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Analysis failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      <div className="flex items-center gap-3 mb-8">
        <Mail className="w-7 h-7 text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">Email Header & Social Engineering Analyzer</h1>
          <p className="text-gray-400 text-sm">
            Paste raw email headers or body — extracts URLs, detects urgency lures, sender spoofing, and mismatched anchor links.
          </p>
        </div>
      </div>

      <div className="card mb-4">
        <label className="text-xs text-gray-400 mb-2 block font-medium">Paste email headers or message body</label>
        <textarea
          className="input text-sm h-48 resize-none font-mono"
          placeholder="Paste email headers or body here..."
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
        />
        <div className="flex gap-3 mt-3 flex-wrap">
          <button onClick={analyze} disabled={loading || !headers.trim()} className="btn-primary flex items-center gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
            Analyze Email
          </button>
          <button onClick={() => setHeaders(SAMPLE)} className="btn-secondary text-sm">
            Load Demo Sample
          </button>
          <button onClick={() => { setHeaders(""); setResult(null); setError(""); }} className="btn-secondary text-sm">
            Clear
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm mb-4">{error}</div>
      )}

      {result && <EmailScanResult result={result} />}
    </div>
  );
}
