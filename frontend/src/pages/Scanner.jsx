import { useState, useCallback, useRef, useEffect } from "react";
import { Search, Upload, Shield, Loader2, Camera, Mail, Video, VideoOff } from "lucide-react";
import { useDropzone } from "react-dropzone";
import jsQR from "jsqr";
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
  const [cameraActive, setCameraActive] = useState(false);
  const [qrDecodedUrl, setQrDecodedUrl] = useState("");

  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const animFrameRef = useRef(null);
  const cameraActiveRef = useRef(false);

  useEffect(() => {
    cameraActiveRef.current = cameraActive;
  }, [cameraActive]);

  // Clean up camera on unmount or tab switch
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, []);

  const stopCamera = () => {
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    setCameraActive(false);
    cameraActiveRef.current = false;
  };

  const triggerScanFromUrl = async (targetUrl) => {
    if (!targetUrl || !targetUrl.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    setQrDecodedUrl(targetUrl);
    try {
      const res = await api.post(`/api/scan/url?screenshot=${withScreenshot}`, {
        url: targetUrl.trim(),
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed. Check API connection.");
    } finally {
      setLoading(false);
    }
  };

  const scanUrl = async (e) => {
    if (e) e.preventDefault();
    triggerScanFromUrl(url);
  };

  const scanEmail = async (e) => {
    if (e) e.preventDefault();
    if (!emailText.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await api.post("/api/scan/email", { headers: emailText });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Email analysis failed. Check API connection.");
    } finally {
      setLoading(false);
    }
  };

  // ── Client-Side Multi-Resolution QR Decoder ────────────────────────────────
  const decodeQRImage = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          try {
            // Optimization for phone camera photos: scale large images to max 1200px
            const maxDim = 1200;
            let width = img.width;
            let height = img.height;
            if (width > maxDim || height > maxDim) {
              const ratio = Math.min(maxDim / width, maxDim / height);
              width = Math.round(width * ratio);
              height = Math.round(height * ratio);
            }

            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d", { willReadFrequently: true });
            canvas.width = width;
            canvas.height = height;
            ctx.drawImage(img, 0, 0, width, height);

            const imgData = ctx.getImageData(0, 0, width, height);
            let code = jsQR(imgData.data, imgData.width, imgData.height, {
              inversionAttempts: "dontInvert",
            });

            // Try inverted if not found (dark mode / stylized QRs)
            if (!code) {
              code = jsQR(imgData.data, imgData.width, imgData.height, {
                inversionAttempts: "onlyInvert",
              });
            }

            // If downscaled and still not found, try full resolution
            if (!code && (img.width !== width || img.height !== height)) {
              canvas.width = img.width;
              canvas.height = img.height;
              ctx.drawImage(img, 0, 0);
              const fullData = ctx.getImageData(0, 0, img.width, img.height);
              code = jsQR(fullData.data, fullData.width, fullData.height, {
                inversionAttempts: "attemptBoth",
              });
            }

            if (code && code.data) {
              resolve(code.data.trim());
            } else {
              reject(new Error("No QR code detected in image"));
            }
          } catch (err) {
            reject(err);
          }
        };
        img.onerror = () => reject(new Error("Failed to load image"));
        img.src = e.target.result;
      };
      reader.onerror = () => reject(new Error("Failed to read file"));
      reader.readAsDataURL(file);
    });
  };

  const onDrop = useCallback(async (files) => {
    if (!files[0]) return;
    setLoading(true);
    setError("");
    setResult(null);
    setQrDecodedUrl("");
    const file = files[0];

    // Pass 1: High-Speed Client-Side Decoding via jsQR
    try {
      const decodedUrl = await decodeQRImage(file);
      await triggerScanFromUrl(decodedUrl);
      return;
    } catch (clientErr) {
      // Pass 2: Server-side Rust pyrxing fallback
      try {
        const form = new FormData();
        form.append("file", file);
        const res = await api.post("/api/scan/qr", form);
        setResult(res.data);
      } catch (err) {
        setError(
          err.response?.data?.detail ||
          "No QR code could be detected. Please ensure the QR code is clearly visible, well-lit, and in focus."
        );
      } finally {
        setLoading(false);
      }
    }
  }, [withScreenshot]);

  // ── Phone Camera Live Scanner ──────────────────────────────────────────────
  const startCamera = async () => {
    setError("");
    setResult(null);
    setQrDecodedUrl("");
    setCameraActive(true);
    cameraActiveRef.current = true;

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute("playsinline", "true");
        await videoRef.current.play();
        requestAnimationFrame(tickCamera);
      }
    } catch (err) {
      stopCamera();
      setError("Camera access error: " + (err.message || "Please grant camera permission in your browser."));
    }
  };

  const tickCamera = () => {
    if (!cameraActiveRef.current || !videoRef.current) return;

    const video = videoRef.current;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      const canvas = document.createElement("canvas");
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: "dontInvert",
      });

      if (code && code.data) {
        if (navigator.vibrate) navigator.vibrate(100);
        const target = code.data.trim();
        stopCamera();
        triggerScanFromUrl(target);
        return;
      }
    }

    animFrameRef.current = requestAnimationFrame(tickCamera);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "image/*": [] },
    multiple: false,
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
            onClick={() => {
              stopCamera();
              setTab(id);
              setResult(null);
              setError("");
              setQrDecodedUrl("");
            }}
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
        <div className="space-y-4">
          {/* Live Phone Camera Scanner Modal / Panel */}
          {cameraActive ? (
            <div className="card relative overflow-hidden bg-black border-2 border-blue-600 rounded-xl p-0 flex flex-col items-center">
              <div className="relative w-full max-w-md aspect-square bg-black overflow-hidden flex items-center justify-center">
                <video
                  ref={videoRef}
                  className="w-full h-full object-cover"
                  playsInline
                  muted
                />
                {/* Aiming Reticle Frame */}
                <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
                  <div className="w-56 h-56 border-2 border-blue-400/80 rounded-2xl relative shadow-[0_0_20px_rgba(59,130,246,0.5)]">
                    <div className="absolute top-0 left-0 w-6 h-6 border-t-4 border-l-4 border-blue-400 -mt-1 -ml-1 rounded-tl"></div>
                    <div className="absolute top-0 right-0 w-6 h-6 border-t-4 border-r-4 border-blue-400 -mt-1 -mr-1 rounded-tr"></div>
                    <div className="absolute bottom-0 left-0 w-6 h-6 border-b-4 border-l-4 border-blue-400 -mb-1 -ml-1 rounded-bl"></div>
                    <div className="absolute bottom-0 right-0 w-6 h-6 border-b-4 border-r-4 border-blue-400 -mb-1 -mr-1 rounded-br"></div>
                    <div className="absolute inset-x-2 top-1/2 h-0.5 bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.8)] animate-pulse"></div>
                  </div>
                </div>
              </div>

              <div className="p-3 w-full flex items-center justify-between bg-gray-950 border-t border-gray-800">
                <span className="text-xs text-gray-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-green-500 animate-ping"></span>
                  Align QR code within reticle
                </span>
                <button
                  onClick={stopCamera}
                  className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
                >
                  <VideoOff className="w-3.5 h-3.5" /> Stop Camera
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Camera Scanner Button */}
              <button
                onClick={startCamera}
                className="card hover:border-blue-500 transition-colors cursor-pointer text-center py-8 flex flex-col items-center justify-center gap-2 group"
              >
                <div className="p-3 rounded-full bg-blue-950/60 border border-blue-800 text-blue-400 group-hover:scale-110 transition-transform">
                  <Video className="w-7 h-7" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Scan with Phone Camera</h3>
                  <p className="text-xs text-gray-400 mt-0.5">Live instant QR recognition from device video</p>
                </div>
              </button>

              {/* File Dropzone */}
              <div
                {...getRootProps()}
                className={`card border-2 border-dashed cursor-pointer text-center py-8 flex flex-col items-center justify-center gap-2 transition-colors ${
                  isDragActive ? "border-blue-500 bg-blue-900/10" : "border-gray-700 hover:border-gray-600"
                }`}
              >
                <input {...getInputProps()} />
                <div className="p-3 rounded-full bg-gray-900 border border-gray-800 text-gray-400">
                  <Upload className="w-7 h-7" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Upload QR Image</h3>
                  <p className="text-xs text-gray-400 mt-0.5">Drop screenshot or choose photo from gallery</p>
                </div>
              </div>
            </div>
          )}

          {/* Decoded URL info banner */}
          {qrDecodedUrl && (
            <div className="p-3 bg-blue-950/30 border border-blue-800/80 rounded-lg text-xs flex items-center justify-between">
              <span className="text-gray-400 font-mono">
                Decoded QR Link: <strong className="text-blue-300 break-all">{qrDecodedUrl}</strong>
              </span>
            </div>
          )}

          {loading && (
            <div className="flex items-center justify-center gap-2 py-4 text-sm text-blue-400">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Analyzing embedded QR link with PhishGuard AI engines...</span>
            </div>
          )}
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
              onClick={() => {
                setEmailText("");
                setResult(null);
                setError("");
              }}
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
