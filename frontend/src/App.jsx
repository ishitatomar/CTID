import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import { ToastProvider } from "./components/ui.jsx";
import Overview from "./pages/Overview.jsx";
import Indicators from "./pages/Indicators.jsx";
import Vulnerabilities from "./pages/Vulnerabilities.jsx";
import Feeds from "./pages/Feeds.jsx";
import Investigate from "./pages/Investigate.jsx";

export default function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Overview />} />
          <Route path="/indicators" element={<Indicators />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/feeds" element={<Feeds />} />
          <Route path="/investigate" element={<Investigate />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ToastProvider>
  );
}
