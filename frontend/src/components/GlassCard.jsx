export default function GlassCard({ children, className = '', style, onClick, ...rest }) {
  return (
    <section
      className={`glass-card ${className}`}
      style={style}
      onClick={onClick}
      aria-live="polite"
      {...rest}
    >
      {children}
    </section>
  )
}
