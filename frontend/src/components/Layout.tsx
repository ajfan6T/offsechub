import { NavLink, Outlet } from "react-router";
import { useAuth, useUser } from "../auth";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/engagements", label: "Engagements" },
  { to: "/clients", label: "Clients" },
  { to: "/library", label: "Finding library" },
];

export function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
      <path
        d="M16 4 6 8.5v6.7c0 6.5 4.2 11.3 10 13 5.8-1.7 10-6.5 10-13V8.5z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="15" r="3.4" fill="currentColor" />
    </svg>
  );
}

export function Layout() {
  const user = useUser();
  const { logout } = useAuth();
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Logo />
          <span>OffsecHub</span>
        </div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? "active" : "")}>
              {n.label}
            </NavLink>
          ))}
          {user.role === "admin" && (
            <>
              <div className="nav-section">Administration</div>
              <NavLink to="/admin/users">Users</NavLink>
              <NavLink to="/admin/audit">Audit log</NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <NavLink to="/settings" className="user-chip">
            <span className="avatar">{initials(user.full_name)}</span>
            <span>
              <strong>{user.full_name}</strong>
              <small>{user.role}</small>
            </span>
          </NavLink>
          <button className="link" onClick={() => logout()}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

export function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");
}
