export default function ForgeLanding() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="border-b">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded bg-primary" />
            <span className="text-xl font-semibold tracking-tight">Forge</span>
          </div>
          <nav className="flex items-center gap-8 text-sm font-medium">
            <a href="/admin/enrollment-tokens" className="hover:text-primary">Enrollment</a>
            <a href="https://github.com" className="hover:text-primary">GitHub</a>
          </nav>
        </div>
      </header>

      <main className="flex flex-1 flex-col items-center justify-center px-6 text-center">
        <div className="max-w-3xl">
          <div className="mb-4 inline-block rounded-full bg-muted px-4 py-1 text-sm font-medium text-muted-foreground">
            In active development
          </div>
          <h1 className="text-6xl font-semibold tracking-tighter sm:text-7xl">
            The deployment platform<br />that updates itself like your apps.
          </h1>
          <p className="mx-auto mt-6 max-w-xl text-xl text-muted-foreground">
            Secure Rust agents. Zero-downtime updates. First-class multi-cloud support.
            Built to be the best self-hosted experience — not another Coolify/Dokploy clone.
          </p>

          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <a
              href="/admin/enrollment-tokens"
              className="inline-flex h-12 items-center justify-center rounded-lg bg-primary px-8 font-medium text-primary-foreground transition hover:bg-primary/90"
            >
              Open Enrollment Tokens
            </a>
            <a
              href="https://github.com"
              className="inline-flex h-12 items-center justify-center rounded-lg border border-border px-8 font-medium transition hover:bg-muted"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </main>

      <footer className="border-t py-8 text-center text-sm text-muted-foreground">
        Forge • Secure by design • Apache-2.0
      </footer>
    </div>
  );
}
