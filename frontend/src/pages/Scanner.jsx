import { useState, useCallback } from "react";
import { Search, Upload, Shield, Loader2, Camera, Mail } from "lucide-react";
import { useDropzone } from "react-dropzone";
import api from "../api/client";
import ScanResult from "../components/ScanResult";
import EmailScanResult from "../components/EmailScanResult";

const SAMPLE_EMAIL = `From: "PayPal Account Security" <support@paypa1-security.com>
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

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("url");
  const [withScreenshot, setWithScreenshot] = useState(false);

  const scanUrl = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await api.post(`/api/scan/url?screenshot=${withScreenshot}`, { url: url.trim() });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed. Check API connection.");
    } finally {
      setLoading(false);
    }
  };

  const scanEmail = async (e) => {
    if (e) e.preventDefault();
    if (!emailText.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await api.post("/api/scan/email", { headers: emailText });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Email analysis failed. Check API connection.");
    } finally {
      setLoading(false);
    }
  };

  const onDrop = useCallback(async (files) => {
    if (!files[0]) return;
    setLoading(true); setError(""); setResult(null);
    const form = new FormData();
    form.append("file", files[0]);
    try {
      const res = await api.post("/api/scan/qr", form);
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "QR scan failed.");
    } finally {
      setLoading(false);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, accept: { "image/*": [] }, multiple: false,
  });

  const TABS = [
    { id: "url", label: "URL Scanner", Icon: Search },
    { id: "qr", label: "QR Code", Icon: Upload },
    { id: "email", label: "Email Inspector", Icon: Mail },
  ];

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      <div className="text-center mb-10">
        <div className="flex justify-center mb-4">
          <div className="bg-blue-900/30 p-4 rounded-full border border-blue-800">
            <Shield className="w-10 h-10 text-blue-400" />
          </div>
        </div>
        <h1 className="text-3xl font-bold text-white mb-2">PhishGuard AI</h1>
        <p className="text-gray-400 text-sm max-w-md mx-auto">
          Enterprise AI phishing detection & threat intelligence — ML model, Brand Camouflage, DGA entropy, QR inspection & email lure analysis.
        </p>
      </div>

      <div className="flex gap-2 mb-4">
        {TABS.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => { setTab(id); setResult(null); setError(""); }}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5 ${
              tab === id ? "bg-blue-600 text-white" : "btn-secondary"
            }`}
          >
            <Icon className="w-4 h-4" />{label}
          </button>
        ))}
      </div>

      {tab === "url" && (
        <>
          <form onSubmit={scanUrl} className="flex gap-2">
            <input
              className="input text-sm"
              placeholder="Enter URL to scan (e.g. kskfnsfksnfksnf.com.randwa, paypal-security.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <button
              type="submit"
              className="btn-primary flex items-center gap-2 whitespace-nowrap"
              disabled={loading || !url.trim()}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Scan
            </button>
          </form>

          {/* Quick Test Samples */}
          <div className="mt-3">
            <span className="text-xs text-gray-500 mr-2">Try quick demo samples:</span>
            <div className="inline-flex gap-1.5 flex-wrap mt-1">
              {[
                { label: "🟢 Legitimate", sampleUrl: "https://www.google.com" },
                { label: "🔴 DGA / Fake TLD", sampleUrl: "kskfnsfksnfksnf.com.randwa" },
                { label: "🛡 Brand Camouflage", sampleUrl: "https://paypal-security-update.com/login" },
                { label: "🔍 Typosquat", sampleUrl: "https://paypa1.com" },
                { label: "⚡ Free Hosting Trap", sampleUrl: "https://test.duckdns.org/verify/account" },
                { label: "🟡 Suspicious IP", sampleUrl: "http://192.168.1.1/admin/login.php" },
              ].map(({ label, sampleUrl }) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setUrl(sampleUrl)}
                  className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs px-2.5 py-1 rounded-md transition-colors border border-gray-700"
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 mt-3 text-sm text-gray-400 cursor-pointer select-none w-fit">
            <input
              type="checkbox"
              checked={withScreenshot}
              onChange={(e) => setWithScreenshot(e.target.checked)}
              className="rounded"
            />
            <Camera className="w-4 h-4" /> Capture screenshot (requires Playwright)
          </label>
        </>
      )}

      {tab === "qr" && (
        <div
          {...getRootProps()}
          className={`card border-2 border-dashed cursor-pointer text-center py-12 transition-colors ${
            isDragActive ? "border-blue-500 bg-blue-900/10" : "border-gray-700 hover:border-gray-600"
          }`}
        >
          <input {...getInputProps()} />
          <Upload className="w-8 h-8 text-gray-500 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">Drop a QR code image here, or click to select</p>
          <p className="text-gray-600 text-xs mt-1">Protected by Brand Camouflage Shield & URL Unmasking</p>
          {loading && <Loader2 className="w-5 h-5 animate-spin text-blue-400 mx-auto mt-3" />}
        </div>
      )}

      {tab === "email" && (
        <div className="card space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1.5 block font-medium">
              Paste Raw Email Content, Headers or Message Body
            </label>
            <textarea
              className="input text-sm h-44 resize-none font-mono"
              placeholder="Paste email headers or full email text here..."
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-2.5 items-center">
            <button
              onClick={scanEmail}
              disabled={loading || !emailText.trim()}
              className="btn-primary flex items-center gap-2 text-sm"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
              Inspect Email
            </button>
            <button
              type="button"
              onClick={() => setEmailText(SAMPLE_EMAIL)}
              className="btn-secondary text-xs"
            >
              Load Demo Phishing Email
            </button>
            <button
              type="button"
              onClick={() => { setEmailText(""); setResult(null); setError(""); }}
              className="btn-secondary text-xs"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      {/* Render Scan Results */}
      {result && (
        result.lures_detected !== undefined || result.email_risk_score !== undefined ? (
          <EmailScanResult result={result} />
        ) : (
          <ScanResult result={result} />
        )
      )}
    </div>
  );
}
