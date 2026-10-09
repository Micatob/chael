import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { Incident, InvestigationResult, NormalizedLog } from '../types';

export const generateDashboardReport = (
  logs: NormalizedLog[],
  incidents: Incident[],
  soarHistory: any[],
  agents: Array<{ hostname: string; online: boolean }> = [],
) => {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();

  doc.setFillColor(13, 17, 23);
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor(0, 212, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('CHAEL-SIEM SUMMARY', 20, 25);
  doc.setTextColor(74, 124, 153);
  doc.setFontSize(10);
  doc.text(`GENERATED: ${new Date().toLocaleString()}`, 20, 32);
  doc.text(`${logs.length} logs · ${incidents.length} incidents · ${soarHistory.length} SOAR actions · ${agents.length} agents`, pageWidth - 20, 32, { align: 'right' });

  const active = incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;
  const critical = incidents.filter((i) => i.risk_score >= 70 && i.status !== 'RESOLVED').length;
  const online = agents.filter((a) => a.online).length;

  doc.setTextColor(0, 0, 0);
  doc.setFontSize(14);
  doc.text('Posture Overview', 20, 55);
  autoTable(doc, {
    startY: 60,
    head: [['Metric', 'Value']],
    body: [
      ['Total logs (current view)', String(logs.length)],
      ['Total incidents', String(incidents.length)],
      ['Active incidents', String(active)],
      ['Critical/high open', String(critical)],
      ['SOAR actions executed', String(soarHistory.length)],
      ['Agents online', `${online}/${agents.length}`],
    ],
    theme: 'striped',
    headStyles: { fillColor: [30, 58, 95] },
  });

  const endY = (doc as any).lastAutoTable.finalY;
  doc.setFontSize(14);
  doc.text('Top Incidents', 20, endY + 15);
  autoTable(doc, {
    startY: endY + 20,
    head: [['Risk', 'Status', 'Description']],
    body: [...incidents]
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 15)
      .map((i) => [String(i.risk_score), i.status, (i.description || '').slice(0, 90)]),
    theme: 'grid',
    headStyles: { fillColor: [30, 58, 95] },
  });

  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(`Confidential - Chael SIEM Summary Export - Page ${i} of ${pageCount}`, pageWidth / 2, doc.internal.pageSize.getHeight() - 10, { align: 'center' });
  }
  doc.save(`Chael_Summary_${new Date().toISOString().slice(0, 10)}.pdf`);
};

export const generateForensicReport = (incident: Incident, result: InvestigationResult) => {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  
  // --- Header ---
  doc.setFillColor(13, 17, 23);
  doc.rect(0, 0, pageWidth, 40, 'F');
  
  doc.setTextColor(0, 212, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('CHAEL-SIEM FORENSICS', 20, 25);
  
  doc.setTextColor(74, 124, 153);
  doc.setFontSize(10);
  doc.text(`REPORT_ID: ${incident.incident_id.toUpperCase()}`, 20, 32);
  doc.text(`GENERATED: ${new Date().toLocaleString()}`, pageWidth - 20, 32, { align: 'right' });

  // --- Summary Section ---
  doc.setTextColor(0, 0, 0);
  doc.setFontSize(14);
  doc.text('Incident Summary', 20, 55);
  
  autoTable(doc, {
    startY: 60,
    head: [['Attribute', 'Value']],
    body: [
      ['Incident ID', incident.incident_id],
      ['Description', incident.description || 'N/A'],
      ['Timestamp', new Date(incident.timestamp).toLocaleString()],
      ['Risk Score', `${incident.risk_score}/100`],
      ['Status', incident.status],
      ['Affected Assets', result.affected_assets.map(a => `${a.hostname} (${a.role})`).join(', ') || 'None identified'],
      ['Attack Classification', result.attack_classification || 'N/A'],
      ['MITRE Technique', result.mitre_technique ? `${result.mitre_technique.id} - ${result.mitre_technique.name} (${result.mitre_technique.tactic})` : 'N/A'],
      ['Confidence Score', `${(result.confidence_score * 100).toFixed(0)}%`]
    ],
    theme: 'striped',
    headStyles: { fillColor: [30, 58, 95] }
  });

  // --- Extracted Indicators ---
  const summaryEnd = (doc as any).lastAutoTable.finalY;
  if (result.indicators_extracted) {
    const ind = result.indicators_extracted;
    const indicatorRows: string[][] = [];
    if (ind.ip_addresses?.length) indicatorRows.push(['IP Addresses', ind.ip_addresses.join(', ')]);
    if (ind.usernames?.length) indicatorRows.push(['Usernames', ind.usernames.join(', ')]);
    if (ind.cve_ids?.length) indicatorRows.push(['CVE IDs', ind.cve_ids.join(', ')]);
    if (ind.file_paths?.length) indicatorRows.push(['File Paths', ind.file_paths.join(', ')]);

    if (indicatorRows.length) {
      doc.setFontSize(14);
      doc.text('Extracted Indicators', 20, summaryEnd + 15);
      autoTable(doc, {
        startY: summaryEnd + 20,
        head: [['Indicator Type', 'Value']],
        body: indicatorRows,
        theme: 'striped',
        headStyles: { fillColor: [140, 30, 30] }
      });
    }
  }

  // --- Walkthrough Section ---
  const finalY = (doc as any).lastAutoTable.finalY || summaryEnd;
  doc.setFontSize(14);
  doc.text('Forensic Walkthrough', 20, finalY + 15);
  
  const walkthroughData = result.walkthrough.map((step, index) => [
    `${index + 1}`,
    step
  ]);

  autoTable(doc, {
    startY: finalY + 20,
    head: [['Step', 'Analysis Narrative']],
    body: walkthroughData,
    columnStyles: {
      0: { cellWidth: 15 },
      1: { cellWidth: 'auto' }
    },
    theme: 'grid',
    headStyles: { fillColor: [30, 58, 95] }
  });

  // --- IOC Matches ---
  const finalY2 = (doc as any).lastAutoTable.finalY;
  doc.setFontSize(14);
  doc.text('IOC Signatures Identified', 20, finalY2 + 15);
  
  const iocData = result.ioc_matches.map(ioc => [
    ioc.ioc,
    ioc.type,
    ioc.context || '',
    `${(ioc.confidence * 100).toFixed(0)}%`
  ]);

  autoTable(doc, {
    startY: finalY2 + 20,
    head: [['Indicator', 'Type', 'Context', 'Confidence']],
    body: iocData,
    theme: 'striped',
    headStyles: { fillColor: [255, 149, 0] },
    columnStyles: {
      0: { cellWidth: 40 },
      1: { cellWidth: 30 },
      2: { cellWidth: 'auto' },
      3: { cellWidth: 25 }
    }
  });

  // --- Roadmap Section ---
  const finalY3 = (doc as any).lastAutoTable.finalY;
  doc.setFontSize(14);
  doc.text('Post-Investigation Roadmap', 20, finalY3 + 15);
  
  const roadmapData = result.follow_up_steps.map((step, index) => [
    `[ ]`,
    step
  ]);

  autoTable(doc, {
    startY: finalY3 + 20,
    head: [['Status', 'Recommended Action']],
    body: roadmapData,
    columnStyles: {
      0: { cellWidth: 20 },
      1: { cellWidth: 'auto' }
    },
    theme: 'plain',
    headStyles: { fillColor: [0, 255, 136] }
  });

  // --- Chain of Custody ---
  const evidence = (incident as any).evidence || [];
  const custodyEnd = (doc as any).lastAutoTable.finalY;
  doc.setFontSize(14);
  doc.text('Chain of Custody', 20, custodyEnd + 15);
  if (evidence.length) {
    autoTable(doc, {
      startY: custodyEnd + 20,
      head: [['Evidence', 'SHA-256 (short)', 'Custody trail', 'Sealed']],
      body: evidence.map((ev: any) => [
        `${ev.type || ''}: ${(ev.title || '').slice(0, 40)}`,
        (ev.sha256 || ev.seal_hash || '').slice(0, 16) || '—',
        ((ev.custody || []).map((c: any) => c.to || c.actor).join(' → ') || ev.collector || '—').slice(0, 60),
        ev.verified ? 'YES' : 'NO',
      ]),
      theme: 'striped',
      headStyles: { fillColor: [30, 58, 95] },
    });
  } else {
    autoTable(doc, {
      startY: custodyEnd + 20,
      head: [['Evidence', 'Status']],
      body: [['No evidence seized for this incident', (incident as any).legal_hold ? 'LEGAL HOLD' : '—']],
      theme: 'plain',
      headStyles: { fillColor: [30, 58, 95] },
    });
  }

  // --- Footer ---
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(
      `Confidential - Chael SIEM Forensic Export - Page ${i} of ${pageCount}`,
      pageWidth / 2,
      doc.internal.pageSize.getHeight() - 10,
      { align: 'center' }
    );
  }

  doc.save(`Chael_Forensic_Report_${incident.incident_id.slice(0, 8)}.pdf`);
};
