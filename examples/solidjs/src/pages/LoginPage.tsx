import { useNavigate } from "@solidjs/router";
import { LoginForm } from "@yackey-labs/yauth-ui-solidjs";

export function LoginPage() {
	const navigate = useNavigate();

	return (
		<>
			<h1>Login</h1>
			<LoginForm onSuccess={() => navigate("/dashboard")} />
			<p style={{ "margin-top": "12px", "font-size": "14px" }}>
				Don't have an account? <a href="/register">Register</a>
			</p>
		</>
	);
}
