import { Navigate, Route, Routes } from "react-router";
import { Layout } from "./components/Layout";
import { ActivityLog } from "./pages/ActivityLog";
import { Clients } from "./pages/Clients";
import { Dashboard } from "./pages/Dashboard";
import { Engagements } from "./pages/Engagements";
import { Library } from "./pages/Library";
import { Settings } from "./pages/Settings";
import { Activity } from "./pages/engagement/Activity";
import { EngagementLayout } from "./pages/engagement/EngagementLayout";
import { EvidencePage } from "./pages/engagement/Evidence";
import { FindingEditor } from "./pages/engagement/FindingEditor";
import { Findings } from "./pages/engagement/Findings";
import { OpLog } from "./pages/engagement/OpLog";
import { Overview } from "./pages/engagement/Overview";
import { Recon } from "./pages/engagement/Recon";
import { Report } from "./pages/engagement/Report";
import { Scope } from "./pages/engagement/Scope";
import { Targets } from "./pages/engagement/Targets";
import { Testing } from "./pages/engagement/Testing";

/** The workspace of an unlocked vault (the VaultGate renders it only then). */
export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="engagements" element={<Engagements />} />
        <Route path="engagements/:engagementId" element={<EngagementLayout />}>
          <Route index element={<Overview />} />
          <Route path="scope" element={<Scope />} />
          <Route path="targets" element={<Targets />} />
          <Route path="recon" element={<Recon />} />
          <Route path="testing" element={<Testing />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/new" element={<FindingEditor />} />
          <Route path="findings/:findingId" element={<FindingEditor />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="oplog" element={<OpLog />} />
          <Route path="report" element={<Report />} />
          <Route path="activity" element={<Activity />} />
        </Route>
        <Route path="clients" element={<Clients />} />
        <Route path="library" element={<Library />} />
        <Route path="activity" element={<ActivityLog />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
