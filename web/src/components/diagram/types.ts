import type { Edge, Node } from '@xyflow/react';
import type { Dot } from '../../lib/query';

export type ComponentNodeData = {
  name: string;
  kind: string;
  kindLabel: string;
  internet: boolean;
  dots: Dot[];
};

export type ZoneNodeData = {
  name: string;
  trust: string;
  trustLabel: string;
  segmented: boolean;
  egressRestricted: boolean;
};

export type FlowEdgeData = {
  label: string;
  /** Names of the data it carries (the label is these, or `over`). */
  carried: string[];
  title: string;
  crossing: boolean;
  /** Perpendicular offset in px, so parallel flows don't overlap. */
  offset: number;
  selfLoop: boolean;
  /** The model says explicitly that it isn't encrypted in transit. */
  unencrypted: boolean;
  dots: Dot[];
};

export type ComponentNode = Node<ComponentNodeData, 'component'>;
export type ZoneNode = Node<ZoneNodeData, 'zone'>;
export type DiagramNode = ComponentNode | ZoneNode;
export type FlowEdge = Edge<FlowEdgeData, 'flow'>;
