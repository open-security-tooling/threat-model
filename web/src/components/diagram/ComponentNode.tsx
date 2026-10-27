import { Handle, Position, type NodeProps } from '@xyflow/react';
import { KindIcon } from './KindIcon';
import { RiskDots } from '../RiskDots';
import { app } from '../../lib/app';
import { useStore } from '../../lib/store';
import type { ComponentNode } from './types';

export function ComponentNodeView({ id, data }: NodeProps<ComponentNode>) {
  useStore(app);
  const selected = app.selection?.type === 'component' && app.selection.id === id;
  const hl = app.highlight;
  const cls = ['comp', selected && 'selected', hl && (hl.components.has(id) ? 'on-path' : 'off-path')].filter(Boolean).join(' ');
  return (
    <div className={cls}>
      {/* Edges attach to invisible handles at the centre and are drawn to the border. */}
      <Handle type="target" id="in" position={Position.Top} className="center-handle" isConnectableStart={false} />
      <Handle type="source" id="c" position={Position.Top} className="center-handle" isConnectable={false} />
      <Handle type="source" id="out" position={Position.Right} className="out-handle" title="Drag to another component to add a flow" />
      <div className="comp-head">
        <span className={`comp-icon kind-${data.kind}`}>
          <KindIcon kind={data.kind} />
        </span>
        <span className="comp-text">
          <span className="comp-name" title={data.name}>
            {data.name}
          </span>
          <span className="comp-kind">
            {data.kindLabel}
            {data.internet && <span className="exposed"> · internet</span>}
          </span>
        </span>
      </div>
      {data.dots.length > 0 && <RiskDots dots={data.dots} onOpen={(t) => app.select('threat', t)} dim={hl?.threats} />}
    </div>
  );
}
