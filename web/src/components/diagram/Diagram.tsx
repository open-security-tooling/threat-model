import { useCallback, useEffect, useRef, useState } from 'react';
import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  ConnectionMode,
  Controls,
  MarkerType,
  ReactFlow,
  type Connection,
  type EdgeChange,
  type EdgeTypes,
  type NodeChange,
  type NodeTypes,
  type OnSelectionChangeParams,
  ViewportPortal,
} from '@xyflow/react';
import { ComponentNodeView } from './ComponentNode';
import { ZoneNodeView, ZoneTitle } from './ZoneNode';
import { FlowEdgeView } from './FlowEdge';
import type { ComponentNode, DiagramNode, FlowEdge, ZoneNode } from './types';
import { app, type Step } from '../../lib/app';
import { useStore } from '../../lib/store';
import { dialogs } from '../../lib/dialogs';
import { theme } from '../../lib/theme';
import { core } from '../../core/client';
import type { Position, View } from '../../core/types';
import { computeLayout, NODE_H, NODE_W, zoneAt, zoneOf, type DiagramLayout, type Rect } from '../../lib/layout';
import * as L from '../../lib/labels';
import { dataName, dotsFor } from '../../lib/query';
import { flowOffsets } from '../../lib/geometry';
import { getPref, setPref } from '../../lib/storage';
import { ElementsList } from './ElementsList';

const nodeTypes: NodeTypes = { component: ComponentNodeView, zone: ZoneNodeView };
const edgeTypes: EdgeTypes = { flow: FlowEdgeView };

// Explicit stacking (React Flow's zIndexMode="manual"): zone areas at the
// bottom, then arrows, then everything with text in it. No label may sit
// beneath an arrow: zone titles (z 20), components (z 30) and flow labels
// (z 40; titles and labels are set in components.css) all sit above edges. React
// Flow would otherwise raise edges between children of zones over labels.
const Z_ZONE = 0;
const Z_EDGE = 10;
const Z_COMPONENT = 30;

// Deleting from the canvas is off (deletes go through the core, with its
// reference checks), so the built-in descriptions mustn't mention it.
const ariaLabelConfig = {
  'node.a11yDescription.default': 'Press enter or space to select it and see its details.',
  'node.a11yDescription.keyboardDisabled': 'Press enter or space to select it and see its details, then use the arrow keys to move it.',
  'edge.a11yDescription.default': 'Press enter or space to select this flow and see its details.',
};

function build(v: View): { nodes: DiagramNode[]; edges: FlowEdge[]; placed: DiagramLayout } {
  const m = v.model;
  const placed = computeLayout(m);
  const zoneNodes: ZoneNode[] = (m.zones ?? []).map((z) => {
    const r = placed.zones.get(z.id)!;
    return {
      id: z.id,
      type: 'zone',
      position: { x: r.x, y: r.y },
      width: r.w,
      height: r.h,
      zIndex: Z_ZONE,
      dragHandle: '.zone-handle',
      ariaLabel: `Zone ${z.name}, ${L.label(L.trusts, z.trust)}${z.network === 'segmented' ? ', segmented' : ''}${z.egress === 'restricted' ? ', egress restricted' : ''}`,
      data: { name: z.name, trust: z.trust, trustLabel: L.label(L.trusts, z.trust), segmented: z.network === 'segmented', egressRestricted: z.egress === 'restricted' },
    };
  });
  const compNodes: ComponentNode[] = (m.components ?? []).map((c) => {
    const r = placed.components.get(c.id)!;
    const zone = zoneOf(m, c.zone);
    const zr = zone ? placed.zones.get(zone) : undefined;
    const dots = dotsFor(v, c.id);
    return {
      id: c.id,
      type: 'component',
      position: zr ? { x: r.x - zr.x, y: r.y - zr.y } : { x: r.x, y: r.y },
      ...(zr ? { parentId: zone } : {}),
      width: NODE_W,
      height: NODE_H,
      zIndex: Z_COMPONENT,
      ariaLabel: `${c.name}, ${L.label(L.componentKinds, c.kind)}${dots.length ? `, ${dots.length} threats` : ''}`,
      data: { name: c.name, kind: c.kind, kindLabel: L.label(L.componentKinds, c.kind), internet: c.exposure === 'internet', dots },
    };
  });

  const ids = new Set(compNodes.map((n) => n.id));
  const crossings = new Set(v.crossings);
  const flows = (m.flows ?? []).filter((f) => ids.has(f.from) && ids.has(f.to));
  const offsets = flowOffsets(flows);
  const edges: FlowEdge[] = flows.map((f) => {
    const offset = offsets.get(f.id) ?? 0;
    const crossing = crossings.has(f.id);
    const carried = (f.carries ?? []).map((d) => dataName(m, d));
    const label = carried.join(', ') || f.over || '';
    const title = [
      carried.length ? `Carries: ${carried.join(', ')}` : '',
      f.over ? `Over: ${f.over}` : '',
      f.auth ? `Auth: ${L.label(L.flowAuths, f.auth)}` : '',
      v.transit?.[f.id] === 'encrypted' ? 'Encrypted in transit' : v.transit?.[f.id] === 'unencrypted' ? 'Not encrypted in transit' : '',
      crossing ? 'Crosses zones' : '',
    ]
      .filter(Boolean)
      .join('\n');
    return {
      id: f.id,
      type: 'flow',
      source: f.from,
      target: f.to,
      sourceHandle: 'c',
      targetHandle: 'in',
      zIndex: Z_EDGE,
      markerEnd: { type: MarkerType.ArrowClosed, color: crossing ? 'var(--edge-crossing)' : 'var(--edge)', width: crossing ? 7 : 16, height: crossing ? 7 : 16 },
      ariaLabel: `Flow from ${f.from} to ${f.to}${label ? `, carries ${label}` : ''}${crossing ? ', crosses zones' : ''}${v.transit?.[f.id] === 'unencrypted' ? ', not encrypted' : ''}`,
      data: { label, carried, title, crossing, offset, selfLoop: f.from === f.to, unencrypted: v.transit?.[f.id] === 'unencrypted', dots: dotsFor(v, f.id) },
    };
  });
  // Parents must come before their children.
  return { nodes: [...zoneNodes, ...compNodes], edges, placed };
}

function absolute(n: DiagramNode, byId: Map<string, DiagramNode>) {
  const parent = n.parentId ? byId.get(n.parentId) : undefined;
  return parent ? { x: parent.position.x + n.position.x, y: parent.position.y + n.position.y } : n.position;
}

const moved = (a: { x: number; y: number }, b: Rect | undefined) => !b || Math.abs(a.x - b.x) > 0.5 || Math.abs(a.y - b.y) > 0.5;

/**
 * The edits for what the user moved. Positions the app chose itself are
 * written at the same time, so nothing else jumps once the file has a
 * layout; until the first move the file isn't touched.
 */
function layoutSteps(v: View, nodes: DiagramNode[], placed: DiagramLayout): Step[] {
  const m = v.model;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const movedIds = new Set(
    nodes.filter((n) => moved(absolute(n, byId), n.type === 'zone' ? placed.zones.get(n.id) : placed.components.get(n.id))).map((n) => n.id),
  );
  if (!movedIds.size) return [];

  const zoneRects = new Map<string, Rect>();
  for (const n of nodes) {
    const r = n.type === 'zone' ? placed.zones.get(n.id) : undefined;
    if (r) zoneRects.set(n.id, { x: n.position.x, y: n.position.y, w: r.w, h: r.h });
  }

  const steps: Step[] = [];
  for (const id of movedIds) {
    const c = m.components?.find((x) => x.id === id);
    if (!c) continue;
    // Dropping a component inside another zone moves it there.
    const p = absolute(byId.get(id)!, byId);
    const target = zoneAt(zoneRects, p.x + NODE_W / 2, p.y + NODE_H / 2);
    if (target && target !== c.zone) steps.push((s) => core.upsert(s, 'components', id, { zone: target }));
  }
  const positions: Record<string, Position> = {};
  for (const n of nodes) {
    const isMoved = movedIds.has(n.id);
    const r = n.type === 'zone' ? placed.zones.get(n.id) : placed.components.get(n.id);
    if (!r || (!isMoved && !r.auto)) continue;
    if (n.type === 'zone') {
      positions[n.id] = { x: Math.round(n.position.x), y: Math.round(n.position.y), w: Math.round(r.w), h: Math.round(r.h) };
    } else {
      const p = absolute(n, byId);
      positions[n.id] = { x: Math.round(p.x), y: Math.round(p.y) };
    }
  }
  // One edit for every position, so the first move is a single change.
  if (Object.keys(positions).length) steps.push((s) => core.setLayouts(s, positions));
  return steps;
}

export function Diagram() {
  useStore(app);
  useStore(theme);
  const view = app.view;
  const [nodes, setNodes] = useState<DiagramNode[]>([]);
  const [asList, setAsList] = useState(() => getPref('diagram-list') === 'on');
  const [edges, setEdges] = useState<FlowEdge[]>([]);
  const nodesRef = useRef<DiagramNode[]>([]);
  const placedRef = useRef<DiagramLayout>({ components: new Map(), zones: new Map() });
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const rebuild = useCallback((v: View) => {
    const b = build(v);
    placedRef.current = b.placed;
    nodesRef.current = b.nodes;
    setNodes(b.nodes);
    setEdges(b.edges);
  }, []);

  useEffect(() => {
    if (view) rebuild(view);
  }, [view, rebuild]);

  const saveLayout = useCallback(async () => {
    clearTimeout(timer.current);
    const v = app.view;
    const current = nodesRef.current;
    if (!v || current.some((n) => n.dragging)) return;
    const steps = layoutSteps(v, current, placedRef.current);
    if (!steps.length) return;
    // A refused edit leaves the source as it was; put the nodes back too.
    if (!(await app.edit(...steps)) && app.view) rebuild(app.view);
  }, [rebuild]);

  useEffect(() => () => clearTimeout(timer.current), []);

  const onNodesChange = useCallback(
    (changes: NodeChange<DiagramNode>[]) => {
      const next = applyNodeChanges(changes, nodesRef.current);
      nodesRef.current = next;
      setNodes(next);
      // Keyboard moves arrive as position changes without a drag; debounce
      // them so a run of arrow presses becomes one edit.
      if (changes.some((c) => c.type === 'position' && !c.dragging)) {
        clearTimeout(timer.current);
        timer.current = setTimeout(() => void saveLayout(), 350);
      }
    },
    [saveLayout],
  );

  const onEdgesChange = useCallback((changes: EdgeChange<FlowEdge>[]) => setEdges((e) => applyEdgeChanges(changes, e)), []);

  // The flow is added by the form through the core, not by the canvas.
  const onConnect = useCallback((c: Connection) => {
    if (c.source && c.target) dialogs.openForm({ section: 'flows', preset: { from: c.source, to: c.target } });
  }, []);

  // Keyboard selection (Enter on a focused node or edge) opens its details
  // too. React Flow calls this again whenever its identity changes, so it
  // must be stable.
  const onSelectionChange = useCallback(({ nodes: ns, edges: es }: OnSelectionChangeParams<DiagramNode, FlowEdge>) => {
    if (ns.length === 1 && !es.length) app.select(ns[0]!.type === 'zone' ? 'zone' : 'component', ns[0]!.id);
    else if (es.length === 1 && !ns.length) app.select('flow', es[0]!.id);
  }, []);

  const empty = view && !(view.model.components ?? []).length;

  const listToggle = (
    <button
      type="button"
      className="btn small view-toggle"
      aria-pressed={asList}
      onClick={() => {
        setAsList(!asList);
        setPref('diagram-list', asList ? null : 'on');
      }}
    >
      {asList ? 'Show as diagram' : 'Show as list'}
    </button>
  );

  if (asList && view) {
    return (
      <div className="diagram" role="region" aria-label="Components and flows">
        {listToggle}
        <ElementsList view={view} />
      </div>
    );
  }

  return (
    <div className="diagram" role="region" aria-label="Diagram. The same information is available as tables: use Show as list.">
      {listToggle}
      <ReactFlow<DiagramNode, FlowEdge>
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeDragStop={() => void saveLayout()}
        onConnect={onConnect}
        onNodeClick={(_, node) => app.select(node.type === 'zone' ? 'zone' : 'component', node.id)}
        onEdgeClick={(_, edge) => app.select('flow', edge.id)}
        onSelectionChange={onSelectionChange}
        colorMode={theme.resolved}
        connectionMode={ConnectionMode.Loose}
        connectionRadius={60}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2}
        maxZoom={2}
        deleteKeyCode={null}
        selectionKeyCode={null}
        multiSelectionKeyCode={null}
        elevateNodesOnSelect={false}
        proOptions={{ hideAttribution: true }}
        ariaLabelConfig={ariaLabelConfig}
        zIndexMode="manual"
        elevateEdgesOnSelect={false}
      >
        <ViewportPortal>
          {nodes.map((n) =>
            n.type === 'zone' ? (
              // A visual copy of the zone's title above the arrows. It ignores
              // the pointer, so dragging still reaches the zone's own handle.
              <div
                key={n.id}
                className="zone-title"
                aria-hidden="true"
                style={{ transform: `translate(${n.position.x + 2}px, ${n.position.y + 2}px)`, maxWidth: (n.width ?? 0) - 4 }}
              >
                <ZoneTitle data={n.data} />
              </div>
            ) : null,
          )}
        </ViewportPortal>
        <Background gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
      {empty && (
        <div className="diagram-empty">
          <p>Nothing here yet.</p>
          <button type="button" className="btn primary" onClick={() => dialogs.openForm({ section: 'components' })}>
            Add a component
          </button>
        </div>
      )}
    </div>
  );
}
