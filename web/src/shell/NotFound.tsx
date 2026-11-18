import { Link } from '@tanstack/react-router';

export function NotFoundPage() {
  return (
    <div className="fullpage">
      <div className="card pad-lg" style={{ maxWidth: 480 }}>
        <h1 className="section-title">Page not found</h1>
        <p className="muted" style={{ margin: 0 }}>
          This address does not exist in Olympos. Check the link, or go back to the fleet overview.
        </p>
        <div className="end">
          <Link to="/" className="btn pri">
            Go to dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
