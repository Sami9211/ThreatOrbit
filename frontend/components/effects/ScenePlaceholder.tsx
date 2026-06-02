/**
 * Lightweight fallback shown while a WebGL scene's lazy chunk loads.
 * A soft centred plasma glow — keeps the layout from flashing empty and
 * hints that something is about to render. Pure CSS, zero JS cost.
 */
export default function ScenePlaceholder() {
  return (
    <div className="w-full h-full flex items-center justify-center" aria-hidden>
      <div
        className="w-1/2 aspect-square rounded-full animate-glow-pulse"
        style={{
          background:
            'radial-gradient(circle, rgba(255,46,151,0.18) 0%, rgba(122,60,255,0.10) 45%, transparent 70%)',
        }}
      />
    </div>
  )
}
