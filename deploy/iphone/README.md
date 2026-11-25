# Open the SOC dashboard on iPhone

The Mac hosts both SOC workspaces. An ngrok Free HTTPS endpoint lets Safari reach the dashboard over cellular. Google sign-in restricts access to the single address you choose. After Google sign-in, each workspace still requires its usual SOC account and MFA. ngrok terminates HTTPS and forwards traffic to the Mac over its encrypted tunnel.

## Start the demo

1. Keep the Mac awake and online, with Docker Desktop, the unified dashboard on port 5173 and the required SOC backends running. For a fresh checkout, build the phone gateway using the commands below.
2. Create or sign in to an **ngrok Free** account. Double-click **Connect iPhone.command** in this folder. Enter the Google email that should have access and paste your ngrok authtoken at the hidden prompt. The launcher sends it directly to the temporary connector. [Get your ngrok authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)
3. Keep the Terminal window open. When ngrok reports a started tunnel, open its `https://` address beside `url=` in iPhone Safari. Tap **Visit Site** if the free-tier notice appears. Sign in with the allowed Google account, choose a SOC workspace and sign in to the dashboard.
4. Select **Share → Add to Home Screen**, enable **Open as Web App**, and tap **Add**. Turn off Wi-Fi on the phone and launch the icon over cellular. Open Alerts and switch workspaces. The Mac must remain reachable for live data. [Apple Home Screen instructions](https://support.apple.com/guide/iphone/open-as-web-app-iphea86e5236/ios)
5. To end the session, press **Control-C** in the launcher. You can also run `docker stop idps-iphone-tunnel` from another terminal. Your ngrok account keeps its assigned address for your next session. [Free plan limits](https://ngrok.com/docs/pricing-limits/free-plan-limits)

The mobile Live Demo page displays the current run and evidence. The gateway forwards browser API routes and keeps lab runner controls local. Choose the permitted Google identity carefully, especially when showing a real SOC. ngrok's free plan has monthly quotas, including 1 GB of outbound data and 20,000 HTTP requests. Close the dashboard after the demo to stop its polling.

## Build and check the gateway

From the repository root, with the project's Node environment and Docker Desktop available, run the following commands.

```sh
npm --prefix soc/web ci
npm --prefix soc/web run build:iphone
docker compose -f deploy/iphone/compose.yml up -d --build gateway
docker compose -f deploy/iphone/compose.yml exec -T gateway curl -fsS http://127.0.0.1:8080/api/health
docker compose -f deploy/iphone/compose.yml exec -T gateway curl -fsS http://127.0.0.1:8080/lab-api/health
```

Both health requests should return JSON with status `ok`. To update the phone app, stop the tunnel, rebuild the frontend and gateway, then reopen the launcher. A 403 after Google sign-in means the signed-in email did not match the launcher's allowlist. A 502 from a SOC route means its upstream service needs attention.
