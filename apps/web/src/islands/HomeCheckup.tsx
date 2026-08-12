import { useState } from 'preact/hooks';
import { CheckupForm } from './CheckupForm';

/**
 * The homepage form.
 *
 * It only collects a domain and hands over to the Health Library, where the
 * diagnosis is read. That keeps the homepage to a single job, and it means the
 * result has a URL of its own that can be shared, bookmarked and indexed.
 */
export default function HomeCheckup() {
  const [leaving, setLeaving] = useState(false);

  return (
    <CheckupForm
      busy={leaving}
      onExamine={(domain) => {
        setLeaving(true);
        location.href = `/health-library?domain=${encodeURIComponent(domain)}`;
      }}
    />
  );
}
