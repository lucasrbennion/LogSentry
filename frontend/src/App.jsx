import React, { useEffect, useState } from "react";
import SummaryCards from "./components/SummaryCards";
import EventTable from "./components/EventTable";
import EventDetailPanel from "./components/EventDetailPanel";
import FilterBar from "./components/FilterBar";

const samplePayload = {
  summary: {
    total_events: 3,
    priority_breakdown: { P2: 1, P3: 1, P4: 1 },
    event_id_breakdown: { 4624: 1, 4625: 1, 4672: 1 },
  },
  results: [
    {
      event_id: 4624,
      timestamp: "2026-05-23T19:00:00",
      account: "testuser1",
      machine_name: "WIN-H96JM6F374S",
      logon_type: "2",
      priority: "P4",
      recommended_owner: "Infrastructure / Operations",
      explanation: "R010: Successful interactive logon by a non-admin test account.",
    },
    {
      event_id: 4625,
      timestamp: "2026-05-23T19:01:00",
      account: "testuser1",
      machine_name: "WIN-H96JM6F374S",
      logon_type: "2",
      priority: "P3",
      recommended_owner: "SOC / Security Operations",
      explanation: "R020: Failed logon detected; requires authentication review.",
    },
    {
      event_id: 4672,
      timestamp: "2026-05-23T19:01:48",
      account: "labadmin",
      machine_name: "WIN-H96JM6F374S",
      logon_type: null,
      priority: "P2",
      recommended_owner: "SOC / Security Operations",
      explanation: "R030: Special privileges assigned to labadmin.",
    },
  ],
};

export default function App() {
  const [data, setData] = useState(samplePayload);
  const [selected, setSelected] = useState(null);
  const [priorityFilter, setPriorityFilter] = useState("ALL");

  useEffect(() => {
    setSelected(samplePayload.results[0]);
  }, []);

  const filteredResults = data.results.filter((row) =>
    priorityFilter === "ALL" ? true : row.priority === priorityFilter
  );

  return (
    <div style={{ fontFamily: "Arial, sans-serif", padding: 24, maxWidth: 1200, margin: "0 auto" }}>
      <h1>LogSentry</h1>
      <p>Rule-based triage and prioritisation of Windows Security Event Logs.</p>

      <SummaryCards summary={data.summary} />
      <FilterBar priorityFilter={priorityFilter} setPriorityFilter={setPriorityFilter} />

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginTop: 16 }}>
        <EventTable rows={filteredResults} onSelect={setSelected} />
        <EventDetailPanel event={selected} />
      </div>
    </div>
  );
}
