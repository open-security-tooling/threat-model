# Web app

Aim for the feel of Excalidraw: open a URL and start drawing, with nothing to install, no account and nothing sent anywhere. Unlike Excalidraw, the drawing *means* something. Boxes are components, arrows are data flows, and the tool reasons about them.

It's hosted at `https://open-security-tooling.github.io/threat-model/`, and `threat serve` runs the exact same app locally.

## First screen

Three choices and nothing else:

- **Open a file.** Drag and drop a `threatmodel.yaml` or pick one. On Chromium browsers it opens with the File System Access API, so **Save writes back to the same file**.
- **Start a new model.** A short guided start, described below.
- **Try an example.** Loads the invoice-service example.

## Guided start

Plain questions, one at a time, each skippable:

1. *What are you building?* Gives the name and description.
2. *Who uses it?* Customers, admins, other services. These become actors.
3. *What are the main pieces?* Pick from tiles like Web app, API, Database, Queue, Third-party API, LLM, CI/CD. These become components.
4. *Which of these can be reached from the internet?* Sets exposure and zones.
5. *What data is worth protecting?* Pick from common types like passwords, personal data, payment data and API keys, then attach each to components.

You end up with a diagram and a first batch of **suggested threats** to go through. That should take about ten minutes, not a workshop.

## Main layout

```
┌────────────────────────────────────────────────────────────────────┐
│ Invoice service ▾       Diagram │ Threats │ Coverage │ Paths  ⚙ ⤓ │
├──────────────────────────────────────────────┬─────────────────────┤
│                                              │ HIGH                │
│   ┌ Public internet ─────┐  ┌ AWS prod ────┐ │ A logged-in customer│
│   │                      │  │              │ │ could read other    │
│   │  [Browser] ──HTTPS──────▶ [API] ●●○    │ │ customers' invoices │
│   │                      │  │    │         │ │ by changing the ID  │
│   └──────────────────────┘  │    ▼         │ │                     │
│                             │  [DB]  ●     │ │ How it works        │
│                             └──────────────┘ │ 1. Sign up…         │
│                                              │ 2. Note the URL…    │
│  ●  = threat, colored by risk                │ 3. Change it…       │
│                                              │                     │
│                                              │ Why high            │
│                                              │ Anyone who signs up │
│                                              │ can do this in a    │
│                                              │ minute, and…        │
│                                              │                     │
│                                              │ Fixes               │
│                                              │ ◐ Check invoice     │
│                                              │   owner  → Low      │
└──────────────────────────────────────────────┴─────────────────────┘
```

### Diagram

- Components are boxes with an icon per `kind`, zones are labelled areas, and flows are arrows labelled with what they carry.
- Flows that **cross zones** are drawn thicker, because that's where to look first.
- Threat dots on components and flows are colored by residual risk. Clicking one opens its card.
- Drag a component into a zone to set its zone. Draw an arrow to create a flow.
- If the file has no `layout`, the app places everything automatically. New components added by an agent appear in a sensible spot.

### Threat card (side panel)

Each card follows the same order: title, **How it works** (the attack steps), **Who could do it**, **How bad**, **Why this risk** (the generated sentence), then **Fixes**. Each fix shows its status and what the risk becomes once it's done. Security mappings (STRIDE, CWE and so on) sit in a collapsed **For security teams** section.

### Threats view

A sortable, filterable table of threats by risk, status, component and kind. It's the triage view: *what do we fix first?*

### Coverage view

A grid with one row per component and one column per threat kind (impersonate, tamper, cover-tracks, leak, disrupt, escalate, plus abuse and manipulate-ai where relevant). Each cell shows the threats found, or *"considered: nothing applies"*, or is empty. Empty cells are the honest to-do list.

### Paths view

The [simulation](simulation.md): pick a starting point ("anyone on the internet") and a target ("payment data"), and see attack paths highlighted on the diagram as numbered steps. Toggle mitigations to see paths break.

### Suggestions

A badge shows *"5 suggested threats"*. Each suggestion has **Add** and **Dismiss** buttons, and dismissing one asks for a one-line reason.

### YAML view

A side-by-side text editor (CodeMirror) showing the live file. Edit on either side and the other updates. Validation errors show inline with plain-language messages, such as *"Flow `browser-to-api` points to `apii`, which doesn't exist. Did you mean `api`?"*

## Saving and sharing

- **Save** writes the YAML back. The Go core, running as WASM, does the edits, so the result is identical to `threat fmt` and comments are preserved.
- **Export** produces a Markdown report, a self-contained HTML report, PNG or SVG of the diagram, or JSON.
- **There are no share links in v1, on purpose.** Putting a threat model in a URL leaks it into browser history, chat link previews and server logs. To share a model, commit the file. See [security](security.md).
- **Local autosave** to browser storage (IndexedDB) is on by default with a visible indicator, can be turned off, and can be cleared with one click. The data never leaves the browser.

## Live sync with `threat serve`

`threat serve` opens the app against a file on disk and **watches it**. When an agent or your editor changes `threatmodel.yaml`, the diagram updates within a second. You can review an agent's threat model edits visually, as they happen, while the file stays the source of truth.

## Quality bar

- Usable with the keyboard alone. Every action is in a command palette (`⌘K`).
- Light and dark themes, and it meets WCAG AA contrast.
- Opens a 200-component model in under a second.
- Works offline once loaded, as an installable PWA.
