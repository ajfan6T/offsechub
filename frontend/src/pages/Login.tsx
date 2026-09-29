import { useState, type FormEvent } from "react";
import { useAuth } from "../auth";
import { Logo } from "../components/Layout";
import { Button } from "../components/ui";

export function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="brand brand-lg">
          <Logo />
          <span>OffsecHub</span>
        </div>
        <p className="muted">Engagement workspace for offensive security teams.</p>
        {error && <div className="alert alert-error">{error}</div>}
        <label className="field">
          <span className="field-label">Email</span>
          <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        </label>
        <label className="field">
          <span className="field-label">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <Button variant="primary" type="submit" loading={busy} className="btn-block">
          Sign in
        </Button>
        <p className="muted small">Authorised use only. All activity is logged.</p>
      </form>
    </div>
  );
}
