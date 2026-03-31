import { Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";

export function DashboardPage() {
  const navigate = useNavigate();
  const { client, user, loading } = useYAuth();

  // user() and loading() are signal accessors — only call inside JSX or effects.
  // Destructuring { client, user, loading } from useYAuth is safe because
  // client is a plain object and user/loading are already accessor functions.

  const handleLogout = async () => {
    await client.logout();
    navigate("/login");
  };

  return (
    <>
      <h1>Dashboard</h1>
      <Show when={!loading()} fallback={<div>Loading...</div>}>
        <Show
          when={user()}
          fallback={
            <div>
              <p>Not logged in.</p>
              <a href="/login">Go to login</a>
            </div>
          }
        >
          {(u) => (
            <div>
              <p>
                Logged in as <strong>{u().email}</strong>
              </p>
              <p
                style={{
                  "margin-top": "8px",
                  color: "#666",
                  "font-size": "14px",
                }}
              >
                Role: {u().role} | Email verified:{" "}
                {u().email_verified ? "Yes" : "No"}
              </p>
              <button style={{ "margin-top": "16px" }} onClick={handleLogout}>
                Logout
              </button>
            </div>
          )}
        </Show>
      </Show>
    </>
  );
}
