import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { AlertRow, Detail, Empty, IncidentCard, Risk, Severity } from '../src/components';
import { alert, incident } from './fixtures';
afterEach(cleanup);

describe('operator display', () => {
  it('renders all four severity labels as text', () => {
    for (const value of ['low', 'medium', 'high', 'critical']) render(<Severity value={value}/>);
    for (const value of ['low', 'medium', 'high', 'critical']) expect(screen.getByText(value)).toBeTruthy();
  });
  it('renders the supplied score out of 100', () => {
    const { container } = render(<Risk value={40}/>);
    expect(container.textContent).toBe('40 / 100');
  });
  it('shows alert entities and opens details on selection', () => {
    const select = vi.fn();
    render(<table><tbody><AlertRow alert={alert()} onSelect={select}/></tbody></table>);
    expect(screen.getByText(/192.0.2.1/)).toBeTruthy();
    expect(screen.getByText('medium')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Basic TCP Port Scan/ }));
    expect(select).toHaveBeenCalledWith(alert());
  });
  it('shows incident risk, status, member count and selection', () => {
    const select = vi.fn();
    render(<IncidentCard incident={incident()} onSelect={select}/>);
    expect(screen.getByText('65')).toBeTruthy();
    expect(screen.getByText('open')).toBeTruthy();
    expect(screen.getByText('2 alerts ↗')).toBeTruthy();
    fireEvent.click(screen.getByRole('button'));
    expect(select).toHaveBeenCalledOnce();
  });
  it('explicitly explains hybrid limitations and member IDs in details', () => {
    render(<Detail kind="incidents" item={incident('i', { incident_type: 'hybrid_activity' })} onClose={() => {}}/>);
    expect(screen.getByText(/does not prove exact process-to-network attribution/)).toBeTruthy();
    expect(screen.getByText('Member Alert IDs (2)')).toBeTruthy();
    expect(screen.getByText('a')).toBeTruthy();
    expect(screen.getByText(/not a calendar date/)).toBeTruthy();
  });
  it('renders a useful empty state', () => {
    render(<Empty>No alerts yet</Empty>);
    expect(screen.getByText('No alerts yet')).toBeTruthy();
  });
});
