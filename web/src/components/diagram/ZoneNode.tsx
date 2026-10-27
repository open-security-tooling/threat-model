import type { NodeProps } from '@xyflow/react';
import { app } from '../../lib/app';
import { useStore } from '../../lib/store';
import type { ZoneNode, ZoneNodeData } from './types';

/** The zone's title line. Drawn twice: visibly above the arrows, and as the drag handle. */
export function ZoneTitle({ data }: { data: ZoneNodeData }) {
  return (
    <>
      <span className="zone-name">{data.name}</span>
      <span className="zone-trust">{data.trustLabel}</span>
      {data.segmented && (
        <span className="zone-tag" title="Only the flows in the model are allowed into this zone">
          segmented
        </span>
      )}
      {data.egressRestricted && (
        <span className="zone-tag" title="Outbound internet traffic only goes to allowed destinations">
          egress restricted
        </span>
      )}
    </>
  );
}

export function ZoneNodeView({ id, data }: NodeProps<ZoneNode>) {
  useStore(app);
  const selected = app.selection?.type === 'zone' && app.selection.id === id;
  return (
    <div className={`zone trust-${data.trust}${data.segmented ? ' segmented' : ''}${selected ? ' selected' : ''}`}>
      <div className="zone-handle" title="Drag to move this zone and everything in it">
        <ZoneTitle data={data} />
      </div>
    </div>
  );
}
