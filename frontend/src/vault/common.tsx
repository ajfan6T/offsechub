import { useState, type ReactNode } from "react";
import { Button, Field, Logo } from "../components/ui";

/** Full-screen centred card used by every screen shown outside an unlocked vault. */
export function VaultScreen({ title, subtitle, wide, children }: { title?: ReactNode; subtitle?: ReactNode; wide?: boolean; children: ReactNode }) {
  return (
    <div className="gate">
      <div className={`gate-card ${wide ? "gate-card-wide" : ""}`}>
        <div className="brand brand-lg">
          <Logo />
          <span>OffsecHub</span>
        </div>
        {title && <h2 className="gate-title">{title}</h2>}
        {subtitle && <div className="muted">{subtitle}</div>}
        {children}
      </div>
    </div>
  );
}

export const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** A filesystem path: always typeable, plus a native picker when the desktop bridge offers one. */
export function PathField({
  label,
  value,
  onChange,
  pick,
  hint,
  placeholder,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (path: string) => void;
  pick?: () => Promise<string | null>;
  hint?: ReactNode;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  const [error, setError] = useState<string | null>(null);
  const browse = async () => {
    setError(null);
    try {
      const picked = await pick!();
      if (picked) onChange(picked);
    } catch (err) {
      setError(errorText(err));
    }
  };
  return (
    <Field label={label} hint={error ? <span className="error-text">{error}</span> : hint}>
      <div className="path-input">
        <input
          className="mono"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          autoFocus={autoFocus}
        />
        {pick && (
          <Button type="button" onClick={browse}>
            Browse…
          </Button>
        )}
      </div>
    </Field>
  );
}

// ------------------------------------------------------------ new password

export const MIN_PASSWORD = 12; // mirrors backend/app/vault/manager.py

export interface NewPassword {
  password: string;
  confirm: string;
}

export const EMPTY_PASSWORD: NewPassword = { password: "", confirm: "" };

export const isValidNewPassword = (v: NewPassword) => v.password.length >= MIN_PASSWORD && v.password === v.confirm;

const COMMON = /password|passw0rd|qwerty|letmein|welcome|iloveyou|admin|offsechub|123456|abcdef/i;
const LABELS = ["Too short", "Weak", "Fair", "Good", "Strong"];

/**
 * Rough strength estimate: length times the size of the character pool, with
 * repeats and well-known patterns discounted. It only needs to steer people
 * away from obviously weak choices; Argon2id does the heavy lifting.
 */
export function passwordStrength(pw: string): number {
  if (pw.length < MIN_PASSWORD) return 0;
  const pool =
    (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/\d/.test(pw) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pw) ? 33 : 0);
  const effective = Math.min(pw.length, new Set(pw).size * 2);
  const bits = effective * Math.log2(pool);
  if (COMMON.test(pw) || bits < 50) return 1;
  return bits < 70 ? 2 : bits < 90 ? 3 : 4;
}

/** Password + confirmation with a strength meter. */
export function NewPasswordFields({
  value,
  onChange,
  label = "Password",
  autoFocus,
}: {
  value: NewPassword;
  onChange: (v: NewPassword) => void;
  label?: string;
  autoFocus?: boolean;
}) {
  const score = passwordStrength(value.password);
  const mismatch = value.confirm !== "" && value.confirm !== value.password;
  return (
    <>
      <Field
        label={label}
        hint={
          value.password ? (
            <span className="strength" data-score={score}>
              <span className="strength-bar" aria-hidden>
                {[1, 2, 3, 4].map((i) => (
                  <span key={i} className={i <= score ? "on" : ""} />
                ))}
              </span>
              {LABELS[score]}
              {score === 0 && ` (${value.password.length}/${MIN_PASSWORD})`}
            </span>
          ) : (
            `At least ${MIN_PASSWORD} characters. A few random words make a strong password that is easy to type.`
          )
        }
      >
        <input
          type="password"
          autoComplete="new-password"
          value={value.password}
          onChange={(e) => onChange({ ...value, password: e.target.value })}
          autoFocus={autoFocus}
        />
      </Field>
      <Field label={`Confirm ${label.toLowerCase()}`} hint={mismatch ? <span className="error-text">Passwords do not match</span> : undefined}>
        <input type="password" autoComplete="new-password" value={value.confirm} onChange={(e) => onChange({ ...value, confirm: e.target.value })} />
      </Field>
    </>
  );
}
