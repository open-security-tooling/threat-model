import type { Dot } from '../lib/query';

const letter: Record<string, string> = { critical: 'C', high: 'H', medium: 'M', low: 'L', na: '–' };

/** Threat dots, colored by residual risk. Each opens its threat card. */
export function RiskDots({ dots, onOpen, max = 6, dim }: { dots: Dot[]; onOpen: (id: string) => void; max?: number; dim?: Set<string> | null }) {
  return (
    <span className="dots nodrag nopan">
      {dots.slice(0, max).map((d) => (
        <button
          key={d.id}
          type="button"
          className={`dot risk-${d.cls}${d.status !== 'open' ? ' settled' : ''}${dim && !dim.has(d.id) ? ' dimmed' : ''}`}
          title={`${d.level}: ${d.title}`}
          aria-label={`${d.level} risk, ${d.status}: ${d.title}`}
          onClick={(e) => {
            e.stopPropagation();
            onOpen(d.id);
          }}
          onPointerDown={(e) => e.stopPropagation()}
        >
          {letter[d.cls] ?? '?'}
        </button>
      ))}
      {dots.length > max && (
        <span className="more" title={`${dots.length - max} more threats`}>
          +{dots.length - max}
        </span>
      )}
    </span>
  );
}
