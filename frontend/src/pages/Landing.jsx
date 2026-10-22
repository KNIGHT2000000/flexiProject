import { Link } from "react-router-dom";
import { Shield, ShieldAlert, Globe, Layers, Mail, BarChart2, Key, Star, ArrowRight } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Landing() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">

      {/* Navbar */}
      <nav className="flex items-center justify-between px-8 py-4 border-b border-gray-800">
        <Link to="/" className="flex items-center gap-2 text-blue-400 font-bold text-xl">
          <Shield className="w-6 h-6" /> PhishGuard AI
        </Link>
        <div className="flex gap-3 items-center">
          <Link to="/scanner" className="text-gray-300 hover:text-white text-sm px-3 py-1.5 transition-colors">
            Online Scanner
          </Link>
          <Link to="/dns-lookup" className="text-gray-300 hover:text-white text-sm px-3 py-1.5 transition-colors hidden sm:block">
            DNS Inspector
          </Link>
          {user ? (
            <Link to="/scanner" className="btn-primary text-sm py-1.5 px-5">
              Launch App
            </Link>
          ) : (
            <>
              <Link to="/login" className="btn-secondary text-sm py-1.5 px-5">Login</Link>
              <Link to="/register" className="btn-primary text-sm py-1.5 px-5">Sign Up Free</Link>
            </>
          )}
        </div>
      </nav>

      {/* Hero */}
      <section className="flex flex-col items-center text-center px-6 py-20 max-w-4xl mx-auto">
        <div className="bg-blue-900/30 border border-blue-800 p-5 rounded-full mb-6">
          <Shield className="w-14 h-14 text-blue-400" />
        </div>
        <h1 className="text-5xl font-extrabold mb-4 leading-tight">
          AI-Powered Phishing<br />
          <span className="text-blue-400">Threat Intelligence Platform</span>
        </h1>
        <p className="text-gray-400 text-lg max-w-xl mb-8">
          Detect malicious URLs and fraudulent domains in real time using machine learning,
          VirusTotal intelligence, WHOIS forensics, SSL verification, and anti-spoofing analysis.
        </p>
        <div className="flex gap-4 flex-wrap justify-center">
          <Link to="/scanner" className="btn-primary text-base px-8 py-3 rounded-xl flex items-center gap-2">
            Try Live Scanner <ArrowRight className="w-4 h-4" />
          </Link>
          {user ? (
            <Link to="/dashboard" className="btn-secondary text-base px-8 py-3 rounded-xl">
              Open Dashboard
            </Link>
          ) : (
            <Link to="/register" className="btn-secondary text-base px-8 py-3 rounded-xl">
              Create Account
            </Link>
          )}
        </div>
        <p className="text-gray-600 text-sm mt-4">Instant scanning · No credit card required · Open API</p>
      </section>

      {/* Features */}
      <section className="bg-gray-900 border-y border-gray-800 py-16 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-2xl font-bold text-center mb-10 text-white">
            Everything you need to detect and neutralize cyber threats
          </h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map((f) => (
              <div key={f.title} className="card flex gap-4 items-start">
                <div className="bg-gray-800 p-2.5 rounded-lg flex-shrink-0">{f.icon}</div>
                <div>
                  <h3 className="font-semibold text-white text-sm mb-1">{f.title}</h3>
                  <p className="text-gray-500 text-xs leading-relaxed">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-6 text-center">
        <h2 className="text-3xl font-bold mb-4">Ready to protect yourself and your organization?</h2>
        <p className="text-gray-400 mb-8">Scan URLs, inspect DNS SPF/DMARC records, and track threats.</p>
        <Link to="/scanner" className="btn-primary text-base px-10 py-3 rounded-xl inline-flex items-center gap-2">
          Start Scanning Now <ArrowRight className="w-4 h-4" />
        </Link>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 px-8 py-5 text-center text-gray-500 text-xs mt-auto flex items-center justify-center gap-2">
        <span>© {new Date().getFullYear()} PhishGuard AI · AI-Powered Phishing Detection & Threat Intelligence Platform</span>
        <span>·</span>
        <a
          href="https://phishguard-pm3q.onrender.com/index.html"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-500 hover:text-blue-400 transition-colors"
          title="Secondary Standby Portal"
        >
          v2.1.0
        </a>
      </footer>
    </div>
  );
}

const FEATURES = [
  {
    icon: <Shield className="w-5 h-5 text-blue-400" />,
    title: "ML-Based Detection",
    desc: "Random Forest model trained on 28 URL features classifies threats in milliseconds.",
  },
  {
    icon: <ShieldAlert className="w-5 h-5 text-red-400" />,
    title: "VirusTotal Integration",
    desc: "Cross-reference URLs against 70+ security engines for comprehensive threat coverage.",
  },
  {
    icon: <Globe className="w-5 h-5 text-green-400" />,
    title: "WHOIS & SSL Analysis",
    desc: "Detect newly registered domains and invalid SSL certificates — common phishing signs.",
  },
  {
    icon: <Layers className="w-5 h-5 text-purple-400" />,
    title: "Bulk URL Scanner",
    desc: "Scan up to 50 URLs at once and download results as a CSV report.",
  },
  {
    icon: <Mail className="w-5 h-5 text-yellow-400" />,
    title: "Email Header Analyzer",
    desc: "Paste raw email headers — all embedded URLs are extracted and scanned automatically.",
  },
  {
    icon: <Key className="w-5 h-5 text-teal-400" />,
    title: "API Access",
    desc: "Generate API keys and integrate PhishGuard into your own apps and workflows.",
  },
];
