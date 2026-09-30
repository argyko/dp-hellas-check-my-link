# DP Hellas Check My Link — Windows

Standalone Windows desktop client. The application does **not** browse the submitted URL locally. It sends the URL over HTTPS to the DP Hellas cloud security engine and displays the returned result.

## Development

1. Install Node.js 20+ and Rust stable.
2. `npm install`
3. Copy `.env.example` to `.env` and set `VITE_CHECK_MY_LINK_DESKTOP_API`.
4. `npm run tauri dev`

## Windows installer

`npm run tauri:build` creates NSIS/MSI installers when run on Windows with the Tauri prerequisites installed.

For reproducible Windows builds from Linux/macOS, use the included GitHub Actions workflow in `.github/workflows/windows-desktop.yml`.

## Security

- No backend API key is shipped in the application.
- The desktop client only calls the BFF endpoint.
- URLs are not opened by the Windows client.
- Use HTTPS in production.
