// The tab bar of Monitoring (docs/design/synthetic-monitoring.md §7): new tabs are added here, by config.
import type { ComponentType } from 'react';
import { SyntheticOverview } from './SyntheticOverview';

export interface MonitoringTab {
  id: 'synthetic';
  label: string;
  component: ComponentType;
}

export const MONITORING_TABS: MonitoringTab[] = [{ id: 'synthetic', label: 'Synthetic', component: SyntheticOverview }];

/** The tab of a ?tab= value; the first tab when it names none. */
export function monitoringTab(id: string | undefined): MonitoringTab {
  return MONITORING_TABS.find((t) => t.id === id) ?? MONITORING_TABS[0];
}
