// One simple line icon per component kind. Static markup only.
export function KindIcon({ kind, size = 20 }: { kind: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {paths(kind)}
    </svg>
  );
}

function paths(kind: string) {
  switch (kind) {
    case 'client':
      return (
        <>
          <rect x="3" y="4" width="18" height="12" rx="1.5" />
          <path d="M8 20h8M12 16v4" />
        </>
      );
    case 'service':
      return (
        <>
          <rect x="4" y="4" width="16" height="6" rx="1.5" />
          <rect x="4" y="14" width="16" height="6" rx="1.5" />
          <path d="M8 7h.01M8 17h.01" />
        </>
      );
    case 'gateway':
      return (
        <>
          <path d="M12 3 4 6v5c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6z" />
          <path d="M8 11h8M8 14.5h8" />
        </>
      );
    case 'database':
      return (
        <>
          <ellipse cx="12" cy="5.5" rx="7" ry="2.5" />
          <path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13" />
          <path d="M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5" />
        </>
      );
    case 'storage':
      return (
        <>
          <path d="M4 7h16l-1.5 12.5a1.5 1.5 0 0 1-1.5 1.5H7a1.5 1.5 0 0 1-1.5-1.5z" />
          <path d="M3 7l2-3h14l2 3" />
        </>
      );
    case 'queue':
      return (
        <>
          <rect x="3" y="8" width="4" height="8" rx="1" />
          <rect x="10" y="8" width="4" height="8" rx="1" />
          <rect x="17" y="8" width="4" height="8" rx="1" />
        </>
      );
    case 'cache':
      return <path d="M13 3 5 13h6l-1 8 8-10h-6z" />;
    case 'identity':
      return (
        <>
          <circle cx="8" cy="14" r="4" />
          <path d="m11 11 9-9M17 5l2 2M15 7l2 2" />
        </>
      );
    case 'third-party':
      return (
        <>
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" />
        </>
      );
    case 'pipeline':
      return (
        <>
          <circle cx="5" cy="12" r="2" />
          <circle cx="19" cy="6" r="2" />
          <circle cx="19" cy="18" r="2" />
          <path d="M7 12h4l6-6M11 12l6 6" />
        </>
      );
    case 'ai':
      return (
        <>
          <path d="M12 3l1.8 4.7L18.5 9.5l-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8z" />
          <path d="M18 15l.9 2.1L21 18l-2.1.9L18 21l-.9-2.1L15 18l2.1-.9z" />
        </>
      );
    default:
      return <rect x="4" y="4" width="16" height="16" rx="3" />;
  }
}
