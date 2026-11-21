import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";

const AdminDashboard = lazy(() => import("./pages/AdminDashboard"));
const EmailScanner = lazy(() => import("./pages/EmailScanner"));
const Landing = lazy(() => import("./pages/Landing"));
const MessageScanner = lazy(() => import("./pages/MessageScanner"));
const UrlScanner = lazy(() => import("./pages/UrlScanner"));

export default function App() {
  return (
    <Suspense fallback={<div className="route-loader">Loading PhishGuard…</div>}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/scanner/url" element={<UrlScanner />} />
          <Route path="/scanner/message" element={<MessageScanner />} />
          <Route path="/scanner/email" element={<EmailScanner />} />
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
