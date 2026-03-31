import { Route, Router } from "@solidjs/router";
import { YAuthProvider } from "@yackey-labs/yauth-ui-solidjs";
import { render } from "solid-js/web";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";

function Nav() {
	return (
		<nav class="nav">
			<a href="/login">Login</a>
			<a href="/register">Register</a>
			<a href="/dashboard">Dashboard</a>
		</nav>
	);
}

function App() {
	return (
		<YAuthProvider baseUrl="/api/auth">
			<div id="app">
				<Nav />
				<div class="card">
					<Router>
						<Route path="/" component={() => <LoginPage />} />
						<Route path="/login" component={() => <LoginPage />} />
						<Route path="/register" component={() => <RegisterPage />} />
						<Route path="/dashboard" component={() => <DashboardPage />} />
					</Router>
				</div>
			</div>
		</YAuthProvider>
	);
}

render(() => <App />, document.getElementById("app")!);
