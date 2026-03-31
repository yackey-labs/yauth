import { useNavigate } from "@solidjs/router";
import { createSignal, Show } from "solid-js";
import { RegisterForm } from "@yackey-labs/yauth-ui-solidjs";

export function RegisterPage() {
  const navigate = useNavigate();
  const [successMessage, setSuccessMessage] = createSignal<string | null>(null);

  const handleSuccess = (message: string) => {
    setSuccessMessage(message || "Registration successful! Please log in.");
    setTimeout(() => navigate("/login"), 2000);
  };

  return (
    <>
      <h1>Register</h1>
      <Show
        when={!successMessage()}
        fallback={<div class="message success">{successMessage()}</div>}
      >
        <RegisterForm onSuccess={handleSuccess} />
      </Show>
      <p style={{ "margin-top": "12px", "font-size": "14px" }}>
        Already have an account? <a href="/login">Login</a>
      </p>
    </>
  );
}
