import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Scans from "./pages/Scans";
import ScanDetail from "./pages/ScanDetail";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}