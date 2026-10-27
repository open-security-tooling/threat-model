import { BaseEdge, EdgeLabelRenderer, type EdgeProps } from '@xyflow/react';
import { RiskDots } from '../RiskDots';
import { app } from '../../lib/app';
import { useStore } from '../../lib/store';
import { edgeGeometry, shortLabel } from '../../lib/geometry';
import type { FlowEdge } from './types';

// Edges attach to handles at the node centres; this draws a straight line
// between the node borders instead, which reads better than fixed sides.
export function FlowEdgeView({ id, sourceX, sourceY, targetX, targetY, data, markerEnd }: EdgeProps<FlowEdge>) {
  useStore(app);
  if (!data) return null;
  const selected = app.selection?.type === 'flow' && app.selection.id === id;
  const g = edgeGeometry({ x: sourceX, y: sourceY }, { x: targetX, y: targetY }, data.offset, data.selfLoop);
  // The text gets the full width; tags and dots wrap onto a row below it when needed.
  const short = shortLabel(data.carried, data.label, g.labelMaxWidth);
  const hl = app.highlight;
  const onPath = hl && data.dots.some((d) => hl.threats.has(d.id));
  return (
    <>
      <BaseEdge
        id={id}
        path={g.path}
        markerEnd={markerEnd}
        interactionWidth={18}
        className={['flow-path', data.crossing && 'crossing', selected && 'is-selected', hl && (onPath ? 'on-path' : 'off-path')].filter(Boolean).join(' ')}
      />
      <EdgeLabelRenderer>
        <div
          className={`flow-label nodrag nopan${selected ? ' is-selected' : ''}`}
          // Capped to the gap between the two boxes; the full text shows on hover and focus.
          style={{ transform: `translate(-50%, -50%) translate(${g.lx}px, ${g.ly}px)`, maxWidth: g.labelMaxWidth }}
        >
          {data.unencrypted && (
            <span className="unencrypted" title="Not encrypted in transit">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round" aria-hidden="true">
                <rect x="4" y="11" width="16" height="10" rx="2" />
                <path d="M8 11V7a4 4 0 0 1 7.5-2" />
              </svg>
              unencrypted
            </span>
          )}
          {data.label && (
            <button type="button" className={`carries${short !== data.label && short.startsWith('Data (') ? ' compact' : ''}`} title={data.title} aria-label={`Flow carrying ${data.label}`} onClick={() => app.select('flow', id)}>
              <span className="carries-short" aria-hidden="true">
                {short}
              </span>
              {short !== data.label && (
                <span className="carries-full" aria-hidden="true">
                  {data.label}
                </span>
              )}
            </button>
          )}
          {data.dots.length > 0 && <RiskDots dots={data.dots} onOpen={(t) => app.select('threat', t)} max={4} dim={hl?.threats} />}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}
