import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import Navbar from "./components/Navbar";
import Landing from "./pages/Landing";
import Scanner from "./pages/Scanner";
import BulkScanner from "./pages/BulkScanner";
import Dashboard from "./pages/Dashboard";
import ThreatFeed from "./pages/ThreatFeed";
import Leaderboard from "./pages/Leaderboard";
import EmailAnalyzer from "./pages/EmailAnalyzer";
import Settings from "./pages/Settings";
import AdminPanel from "./pages/AdminPanel";
import Login from "./pages/Login";
import Register from "./pages/Register";

import DNSInspector from "./pages/DNSInspector";
import SystemStatus from "./pages/SystemStatus";

// Redirects to /login if not authenticated
function PrivateRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  return user ? children : <Navigate to="/login" replace />;
}

// Shows auth pages only to non-authenticated users
function GuestRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  return user ? <Navigate to="/scanner" replace /> : children;
}

function AppRoutes() {
  return (
    <Routes>
      {/* Public landing */}
      <Route path="/" element={<Landing />} />

      {/* Auth pages */}
      <Route path="/login" element={<GuestRoute><Login /></GuestRoute>} />
      <Route path="/register" element={<GuestRoute><Register /></GuestRoute>} />

      {/* Core Scanners & Threat Tools (available to everyone) */}
      <Route path="/scanner" element={<WithNav><Scanner /></WithNav>} />
      <Route path="/bulk" element={<WithNav><BulkScanner /></WithNav>} />
      <Route path="/dns-lookup" element={<WithNav><DNSInspector /></WithNav>} />
      <Route path="/email-analyzer" element={<WithNav><EmailAnalyzer /></WithNav>} />
      <Route path="/feed" element={<WithNav><ThreatFeed /></WithNav>} />
      <Route path="/leaderboard" element={<WithNav><Leaderboard /></WithNav>} />
      <Route path="/system" element={<WithNav><SystemStatus /></WithNav>} />

      {/* Authenticated user dashboard & management */}
      <Route path="/dashboard" element={<PrivateRoute><WithNav><Dashboard /></WithNav></PrivateRoute>} />
      <Route path="/settings" element={<PrivateRoute><WithNav><Settings /></WithNav></PrivateRoute>} />
      <Route path="/admin" element={<PrivateRoute><WithNav><AdminPanel /></WithNav></PrivateRoute>} />

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function WithNav({ children }) {
  return (
    <div className="min-h-screen">
      <Navbar />
      <main>{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </ThemeProvider>
    </AuthProvider>
  );
}
